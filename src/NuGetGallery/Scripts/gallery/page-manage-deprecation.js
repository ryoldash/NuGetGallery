﻿'use strict';

function ManageDeprecationSecurityDetailListViewModel(title, label, placeholder) {
    var self = this;

    this.title = ko.observable(title);
    this.label = ko.observable(label);
    this.placeholder = ko.observable(placeholder);

    this.hasIds = ko.observable(false);
    this.addedIds = ko.observableArray();
    this.ids = ko.pureComputed(function () {
        if (self.hasIds()) {
            return self.addedIds();
        } else {
            return [];
        }
    }, this);
    this.addId = ko.observable('');
    this.add = function () {
        self.addedIds.push(self.addId());
        self.addId('');
    };

    this.remove = function (id) {
        self.addedIds.remove(id);
    };

    this.import = function (ids) {
        var hasIds = ids !== null && ids.length;
        self.hasIds(hasIds);
        if (hasIds) {
            self.addedIds(ids);
        } else {
            self.addedIds.removeAll();
        }
    };

    this.export = function () {
        // Copy the array. 
        // Otherwise, the value returned by this function will change based on the UI.
        return self.ids().slice(0);
    };
}

function ManageDeprecationViewModel(id, versionsDictionary, defaultVersion, submitUrl, packageUrl, getAlternatePackageVersions) {
    var self = this;

    this.versionFilter = ko.observable('');
    this.versions = Object.keys(versionsDictionary).map(function (version) {
        var checked = ko.observable(false);
        var visible = ko.pureComputed(function () {
            return version.startsWith(self.versionFilter());
        });

        return {
            version: version,
            checked: checked,
            visible: visible,
            selected: ko.pureComputed(function () {
                return checked() && visible();
            })
        };
    });
    this.chosenVersions = ko.pureComputed(function () {
        var selected = [];
        for (var index in self.versions) {
            var version = self.versions[index];
            if (version.selected()) {
                selected.push(version.version);
            }
        }

        return selected;
    }, this);
    this.chosenVersionsCount = ko.pureComputed(function () {
        var versions = self.chosenVersions();
        if (!versions) {
            return 0;
        }

        return versions.length;
    }, this);
    this.chosenVersionsCountString = ko.pureComputed(function () {
        var versionsCount = self.chosenVersionsCount();
        var pluralString = versionsCount !== 1 ? "s" : "";
        return versionsCount + " version" + pluralString + " selected out of " + self.versions.length;
    }, this);
    this.hasVersions = ko.pureComputed(function () {
        return self.chosenVersionsCount() > 0;
    }, this);

    this.versionSelectAllChecked = ko.pureComputed(function () {
        for (var index in self.versions) {
            var version = self.versions[index];
            if (version.visible() && !version.checked()) {
                return false;
            }
        }

        return true;
    }, this);
    this.toggleVersionSelectAll = function () {
        var checked = !self.versionSelectAllChecked();
        for (var index in self.versions) {
            var version = self.versions[index];
            if (version.visible()) {
                version.checked(checked);
            }
        }

        return true;
    };

    this.isVulnerable = ko.observable(false);
    this.isLegacy = ko.observable(false);
    this.isOther = ko.observable(false);

    this.cves = new ManageDeprecationSecurityDetailListViewModel(
        "CVE ID(s)",
        "You can provide a list of CVEs applicable to the vulnerability.",
        "Add CVE by ID e.g. CVE-2014-999999, CVE-2015-888888");

    this.hasCvss = ko.observable(false);
    this.selectedCvssRating = ko.observable(0);
    this.cvssRatingLabel = ko.pureComputed(function () {
        var rating = self.selectedCvssRating();
        if (!rating) {
            return '';
        }

        var ratingFloat = parseFloat(rating);
        if (isNaN(ratingFloat) || ratingFloat < 0 || ratingFloat > 10) {
            return 'Invalid CVSS rating!';
        }

        if (ratingFloat < 4) {
            return 'Low';
        }

        if (ratingFloat < 7) {
            return 'Medium';
        }

        if (ratingFloat < 9) {
            return 'High';
        }

        return 'Critical';
    }, this);
    this.cvssRating = ko.pureComputed(function () {
        if (self.hasCvss()) {
            return self.selectedCvssRating();
        } else {
            return null;
        }
    }, this);

    this.cwes = new ManageDeprecationSecurityDetailListViewModel(
        "CWE(s)",
        "You can add one or more CWEs applicable to the vulnerability.",
        "Add CWE by ID or title");
    
    this.chosenAlternatePackageId = ko.observable('');
    this.chosenAlternatePackageVersion = ko.observable();
    this.alternatePackageVersionsCached = ko.observableArray();
    this.alternatePackageVersions = ko.pureComputed(function () {
        return [strings_AnyVersion].concat(self.alternatePackageVersionsCached());
    }, this);
    this.hasAlternatePackageVersions = ko.pureComputed(function () {
        return self.alternatePackageVersionsCached().length > 0;
    }, this);

    this.chosenAlternatePackageIdError = ko.observable();
    this.chosenAlternatePackageId.subscribe(function (id) {
        if (!id) {
            // If the user hasn't input an ID, don't query the server.
            self.chosenAlternatePackageIdError(null);
            return;
        }

        $.ajax({
            url: getAlternatePackageVersions,
            dataType: 'json',
            type: 'GET',
            data: {
                id: id
            },

            statusCode: {
                200: function (data) {
                    if (self.alternatePackageId() === id) {
                        self.alternatePackageVersionsCached(data);
                        self.chosenAlternatePackageIdError(null);
                    }
                },

                404: function () {
                    if (self.alternatePackageId() === id) {
                        self.alternatePackageVersionsCached.removeAll();
                        self.chosenAlternatePackageIdError("Could not find alternate package '" + id + "'.");
                    }
                }
            },

            error: function () {
                if (self.alternatePackageId() === id) {
                    self.alternatePackageVersionsCached.removeAll();
                    self.chosenAlternatePackageIdError("An unknown occurred when searching for alternate package '" + id + "'.");
                }
            }
        });
    }, this);

    this.alternatePackageId = ko.pureComputed(function () {
        if (self.isLegacy()) {
            return self.chosenAlternatePackageId();
        } else {
            return null;
        }
    }, this);
    this.alternatePackageVersion = ko.pureComputed(function () {
        if (self.alternatePackageId()) {
            var version = self.chosenAlternatePackageVersion();
            if (version !== strings_AnyVersion) {
                return version;
            }
        }

        return null;
    }, this);

    this.customMessage = ko.observable('');
    this.shouldUnlist = ko.observable(true);

    this.submitError = ko.observable();
    this.submit = function () {
        self.submitError(null);
        $.ajax({
            url: submitUrl,
            dataType: 'json',
            type: 'POST',
            data: window.nuget.addAjaxAntiForgeryToken({
                id: id,
                versions: self.chosenVersions(),
                isVulnerable: self.isVulnerable(),
                isLegacy: self.isLegacy(),
                isOther: self.isOther(),
                cveIds: self.cves.export(),
                cvssRating: self.cvssRating(),
                cweIds: self.cwes.export(),
                alternatePackageId: self.alternatePackageId(),
                alternatePackageVersion: self.alternatePackageVersion(),
                customMessage: self.customMessage(),
                shouldUnlist: self.shouldUnlist()
            }),
            success: function () {
                window.location.href = packageUrl;
            },
            error: function (jqXHR) {
                var newError = jqXHR && jqXHR.responseJSON ? jqXHR.responseJSON.error : "An unknown error occurred when submitting the form.";
                self.submitError(newError);
            }
        });
    };

    this.chosenVersions.subscribe(function (oldVersions) {
        if (!oldVersions || oldVersions.length !== 1) {
            return;
        }

        var version = versionsDictionary[oldVersions[0]];
        if (!version) {
            return;
        }

        version.IsVulnerable = self.isVulnerable();
        version.IsLegacy = self.isLegacy();
        version.IsOther = self.isOther();
        version.CVEIds = self.cves.export();
        version.CVSSRating = self.cvssRating();
        version.CWEIds = self.cwes.export();
        version.AlternatePackageId = self.alternatePackageId();
        version.AlternatePackageVersion = self.alternatePackageVersion();
        version.CustomMessage = self.customMessage();
        version.ShouldUnlist = self.shouldUnlist();
    }, this, "beforeChange");
    this.chosenVersions.subscribe(function (newVersions) {
        self.alternatePackageVersionsCached([]);

        if (!newVersions || newVersions.length !== 1) {
            return;
        }

        var version = versionsDictionary[newVersions[0]];
        if (!version) {
            return;
        }

        self.isVulnerable(version.IsVulnerable);
        self.isLegacy(version.IsLegacy);
        self.isOther(version.IsOther);

        self.cves.import(version.CVEIds);

        self.hasCvss(version.CVSSRating);
        self.selectedCvssRating(version.CVSSRating);

        self.cwes.import(version.CWEIds);

        self.chosenAlternatePackageId(version.AlternatePackageId);
        if (version.AlternatePackageVersion) {
            self.alternatePackageVersionsCached([version.AlternatePackageVersion]);
            self.chosenAlternatePackageVersion(version.AlternatePackageVersion);
        }

        self.customMessage(version.CustomMessage);
        self.shouldUnlist(version.ShouldUnlist);
    }, this);
    if (versionsDictionary[defaultVersion]) {
        for (var index in self.versions) {
            var version = self.versions[index];
            if (version.version === defaultVersion) {
                version.checked(true);
            } else {
                version.checked(false);
            }
        }
    }

    ko.applyBindings(this, $(".page-manage-deprecation")[0]);
}