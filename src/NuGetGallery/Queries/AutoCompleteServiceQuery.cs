// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using NuGet.Services.Search.Client;
using NuGet.Versioning;
using NuGetGallery.Configuration;

namespace NuGetGallery
{
    public class AutoCompleteServiceQuery
    {
        private readonly ServiceDiscoveryClient _serviceDiscoveryClient;
        private readonly string _autocompleteServiceResourceType;
        private readonly IHttpClientWrapper _httpClient;
        private readonly IHttpClientWrapper _httpClientTM;
        private readonly Uri _autocompleteSearchServiceUri;

        public AutoCompleteServiceQuery(IAppConfiguration configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            _serviceDiscoveryClient = new ServiceDiscoveryClient(configuration.ServiceDiscoveryUri);
            _autocompleteServiceResourceType = configuration.AutocompleteServiceResourceType;
            _httpClient = new RetryingHttpClientWrapper(new HttpClient(), QuietLog.LogHandledException);

            _autocompleteSearchServiceUri = configuration.AutocompleteSearchServiceUri;
            _httpClientTM = new RetryingHttpClientWrapper2(credentials: null, onException: QuietLog.LogHandledException);
        }

        public async Task<IEnumerable<string>> RunServiceQuery(
            string queryString, 
            bool? includePrerelease,
            string semVerLevel = null)
        {
            queryString = BuildQueryString(queryString, includePrerelease, semVerLevel);

            var endpoints = await _serviceDiscoveryClient.GetEndpointsForResourceType(_autocompleteServiceResourceType);
            endpoints = endpoints.Select(e => new Uri(e + queryString)).AsEnumerable();

            var result = await _httpClient.GetStringAsync(endpoints);
            var resultObject = JObject.Parse(result);

            return resultObject["data"].Select(entry => entry.ToString());
        }

        internal string BuildQueryString(string queryString, bool? includePrerelease, string semVerLevel = null)
        {
            queryString += $"&prerelease={includePrerelease ?? false}";

            NuGetVersion semVerLevelVersion;
            if (!string.IsNullOrEmpty(semVerLevel) && NuGetVersion.TryParse(semVerLevel, out semVerLevelVersion))
            {
                queryString += $"&semVerLevel={semVerLevel}";
            }

            if (string.IsNullOrEmpty(queryString))
            {
                return string.Empty;
            }

            return "?" + queryString.TrimStart('&');
        }
    }
}