// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.CommandLineUtils;
using Newtonsoft.Json;
using NuGet.Packaging;
using NuGet.Services.Entities;
using NuGet.VerifyMicrosoftPackage.Fakes;
using NuGetGallery;
using NuGetGallery.Packaging;
using NuGetGallery.Security;

namespace NuGet.VerifyMicrosoftPackage
{
    public class Application : CommandLineApplication
    {
        private readonly ConsoleColor _originalColor;
        private readonly TextWriter _console;
        private readonly CommandOption _versionOption;
        private readonly CommandOption _helpOption;
        private readonly CommandOption _recursiveOption;
        private readonly CommandOption _ruleSetOption;
        private readonly CommandArgument _pathsArgument;
        private readonly Assembly _thisAssembly;

        public Application(TextWriter console)
        {
            _originalColor = Console.ForegroundColor;
            _console = console;
            Out = console;
            Error = console;

            _thisAssembly = typeof(Application).Assembly;

            Name = _thisAssembly.GetName().Name;
            FullName = Name;
            ShortVersionGetter = () => _thisAssembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            LongVersionGetter = ShortVersionGetter;

            Description =
                "This tool determines if a .nupkg meets the metadata requirements for Microsoft packages" +
                Environment.NewLine +
                "on nuget.org. Relative paths and wildcards in the file name are supported. Globbing and" +
                Environment.NewLine +
                "wildcards in the directory are not supported.";

            _versionOption = Option(
                "-v | --version",
                "Show version information.",
                CommandOptionType.NoValue);

            _helpOption = Option(
                "-? | -h | --help",
                "Show help information.",
                CommandOptionType.NoValue);

            _recursiveOption = Option(
                "--recursive",
                "Evaluate wildcards recursively into child directories.",
                CommandOptionType.NoValue);

            _ruleSetOption = Option(
                "--rule-set",
                "A path to a JSON rule set file. See the default below.",
                CommandOptionType.SingleValue);

            _pathsArgument = Argument(
                "PATHS",
                "One or more file paths to a package (.nupkg).",
                multipleValues: true);

            OnExecute(() => ExecuteAsync());
        }

        private async Task<int> ExecuteAsync()
        {
            if (_helpOption.HasValue())
            {
                ShowHelp();
                return -1;
            }

            if (_versionOption.HasValue())
            {
                _console.WriteLine(ShortVersionGetter());

                var commitId = _thisAssembly
                    .GetCustomAttributes<AssemblyMetadataAttribute>()
                    .Where(x => x.Key == "CommitId")
                    .FirstOrDefault();
                if (commitId != null)
                {
                    _console.WriteLine($"Commit ID: {commitId.Value}");
                }

                return -1;
            }

            if (_pathsArgument.Values.Count == 0)
            {
                ShowHelp();
                return -1;
            }

            var packageService = GetPackageService();

            RequirePackageMetadataState state;
            if (_ruleSetOption.HasValue())
            {
                _console.WriteLine("Using rule set from this path:");
                _console.WriteLine(_ruleSetOption.Value());
                var json = File.ReadAllText(_ruleSetOption.Value());
                state = RequirePackageMetadataComplianceUtility.DeserializeState(new[]
                {
                    new UserSecurityPolicy(string.Empty, string.Empty, json),
                });
            }
            else
            {
                state = GetDefaultRuleSet();
            }

            // Iterate over each argument.
            var validCount = 0;
            var invalidCount = 0;
            foreach (var path in _pathsArgument.Values)
            {
                if (string.IsNullOrWhiteSpace(path))
                {
                    continue;
                }

                _console.WriteLine("Using the following package path argument:");
                _console.WriteLine(path);
                _console.WriteLine();

                var directory = Path.GetDirectoryName(path);
                if (string.IsNullOrEmpty(directory))
                {
                    directory = ".";
                }

                var fileName = Path.GetFileName(path);

                IEnumerable<string> paths;
                if (fileName.Contains("*"))
                {
                    paths = Directory.EnumerateFiles(
                        directory,
                        fileName,
                        _recursiveOption.HasValue() ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
                }
                else
                {
                    paths = new[] { path };
                }

                foreach (var packagePath in paths)
                {
                    if (await IsValidAsync(packageService, state, packagePath))
                    {
                        validCount++;
                    }
                    else
                    {
                        invalidCount++;
                    }
                }
            }

            // Summarize the results.
            _console.WriteLine($"Valid package count: {validCount}");
            _console.WriteLine($"Invalid package count: {invalidCount}");

            if (invalidCount > 0)
            {
                _console.WriteLine();
                _console.WriteLine("The metadata validation used the following property names and JSON ruleset.");
                _console.WriteLine();

                var sb = new StringBuilder();
                GetPropertyNamesAndRuleSet(sb, state);
                _console.WriteLine(sb.ToString());
            }

            return invalidCount;
        }

        private static PackageService GetPackageService()
        {
            var packageRegistrationRepository = new FakeEntityRepository<PackageRegistration>();
            var packageRepository = new FakeEntityRepository<Package>();
            var certificateRepository = new FakeEntityRepository<Certificate>();
            var auditingService = new FakeAuditingService();
            var telemetryService = new FakeTelemetryService();
            var securityPolicyService = new FakeSecurityPolicyService();

            var packageService = new PackageService(
                packageRegistrationRepository,
                packageRepository,
                certificateRepository,
                auditingService,
                telemetryService,
                securityPolicyService);
            return packageService;
        }

        private async Task<bool> IsValidAsync(
            IPackageService packageService,
            RequirePackageMetadataState state,
            string packagePath)
        {
            if (!File.Exists(packagePath) && !Directory.Exists(packagePath))
            {
                OutputColor(
                    ConsoleColor.Red,
                    () =>
                    {
                        _console.WriteLine("INVALID.");
                        _console.WriteLine(packagePath);
                        _console.WriteLine("The path does not exist.");
                    });
                return false;
            }

            if (File.GetAttributes(packagePath).HasFlag(FileAttributes.Directory))
            {
                OutputColor(
                    ConsoleColor.Red,
                    () =>
                    {
                        _console.WriteLine("INVALID.");
                        _console.WriteLine(packagePath);
                        _console.WriteLine("The path is a directory, not a file.");
                    });
                return false;
            }

            Package package;
            using (var packageStream = File.OpenRead(packagePath))
            {
                var packageArchiveReader = new PackageArchiveReader(packageStream);

                var packageStreamMetadata = new PackageStreamMetadata
                {
                    HashAlgorithm = CoreConstants.Sha512HashAlgorithmId,
                    Hash = CryptographyService.GenerateHash(
                        packageStream.AsSeekableStream(),
                        CoreConstants.Sha512HashAlgorithmId),
                    Size = packageStream.Length
                };

                var owner = new User();
                var currentUser = owner;
                var isVerified = true;

                package = await packageService.CreatePackageAsync(
                    packageArchiveReader,
                    packageStreamMetadata,
                    owner,
                    currentUser,
                    isVerified);
            }

            var isCompliant = RequirePackageMetadataComplianceUtility.IsPackageMetadataCompliant(
                package,
                state,
                out var complianceFailures);

            if (isCompliant)
            {
                OutputColor(
                    ConsoleColor.Green,
                    () =>
                    {
                        _console.WriteLine("VALID.");
                        _console.WriteLine(packagePath);
                        _console.WriteLine($"The package {package.Id} {package.Version} is compliant.");
                    });
                return true;
            }
            else
            {
                OutputColor(
                    ConsoleColor.Red,
                    () =>
                    {
                        var single = complianceFailures.Count == 1;
                        _console.WriteLine("INVALID.");
                        _console.WriteLine(packagePath);
                        _console.WriteLine($"The package {package.Id} {package.Version} is not compliant.");
                        _console.WriteLine($"There {(single ? "is" : "are")} {complianceFailures.Count} problem{(single ? string.Empty : "s")}.");
                        foreach (var failure in complianceFailures)
                        {
                            _console.WriteLine($"  - {failure}");
                        }
                    });
                return false;
            }
        }

        public void OutputColor(ConsoleColor color, Action output)
        {
            Console.ForegroundColor = color;
            output();
            Console.ForegroundColor = _originalColor;
            _console.WriteLine();
        }

        private static RequirePackageMetadataState GetDefaultRuleSet()
        {
            var subscription = new MicrosoftTeamSubscription();
            var policies = subscription.Policies;
            var state = RequirePackageMetadataComplianceUtility.DeserializeState(policies);
            return state;
        }

        private static void GetPropertyNamesAndRuleSet(StringBuilder sb, RequirePackageMetadataState state)
        {
            // Determine more the .NET property names... which are more readable.
            var properties = typeof(RequirePackageMetadataState)
                .GetProperties(BindingFlags.Instance | BindingFlags.Public)
                .OrderBy(x => x.Name);
            var firstHeading = "Readable .NET Name";
            var maxPropertyName = Math.Max(properties.Max(x => x.Name.Length), firstHeading.Length);
            sb.AppendLine($"{firstHeading.PadRight(maxPropertyName)} | JSON Name");
            sb.AppendLine($"{new string('-', maxPropertyName)} | ----------");
            foreach (var property in properties)
            {
                var jsonProperty = property.GetCustomAttribute<JsonPropertyAttribute>();
                if (jsonProperty != null)
                {
                    sb.AppendLine($"{property.Name.PadRight(maxPropertyName)} | {jsonProperty.PropertyName}");
                }
                else
                {
                    sb.AppendLine($"{property.Name.PadRight(maxPropertyName)} | {property.Name}");
                }
            }

            // Display the JSON ruleset
            sb.AppendLine();
            sb.AppendLine(JsonConvert.SerializeObject(state, Formatting.Indented));
        }

        public override string GetHelpText(string commandName = null)
        {
            var sb = new StringBuilder();

            sb.AppendLine(base.GetHelpText(commandName));
            sb.AppendLine(Description);
            sb.AppendLine();
            sb.AppendLine("The default rule set used for validation is the following:");
            sb.AppendLine();
            GetPropertyNamesAndRuleSet(sb, GetDefaultRuleSet());

            return sb.ToString();
        }
    }
}
