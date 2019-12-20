/**
 * common $resources for Confidant
 */
(function(angular) {
    'use strict';

    angular.module('confidant.history.services.archive', [
        'ngResource',
        'confidant.resources.services'
    ])

    .service('history.ResourceArchiveService', [
        '$log',
        '$q',
        'credentials.archiveList',
        'blindcredentials.archiveList',
        'services.archiveList',
        function($log, $q, CredentialArchive, BlindCredentialArchive, ServiceArchive) {
            var _this = this;
            this.resourceArchive = {
                'credentials': {
                    'service': CredentialArchive,
                    'archive': [],
                    'next_page': null
                },
                'blind_credentials': {
                    'service': BlindCredentialArchive,
                    'archive': [],
                    'next_page': null
                },
                'services': {
                    'service': ServiceArchive,
                    'archive': [],
                    'next_page': null
                }
            };
            this.resourceArchiveVersion = 0;
            this.limit = null;

            function bumpVersion() {
                _this.resourceArchiveVersion = _this.resourceArchiveVersion + 1;
            }

            function doQuery(service, page, limit) {
                limit = limit || _this.limit;
                page = page || null;
                var defer = $q.defer();
                service.get({'page': page, 'limit': limit}).$promise.then(function(result) {
                    defer.resolve(result);
                });
                return defer.promise;
            }

            function mungeResourceData(data, type) {
                data.forEach(function(resource){
                    resource.type = type;
                    resource.modified_date = new Date(resource.modified_date);
                    if (type === 'services') {
                        // For consistency, everything has a name, so we'll set the service name from its ID.
                        // The ID is name-revision, so we need to split and take the first item.
                        resource.name = resource.id.split('-')[0];
                    }
                });
            }

            function queryUntilItem(service, type, item, data, page, count) {
                data = data || [];
                page = page || null;
                count = count || 0;
                var max = 10,
                    defer = $q.defer();

                doQuery(service, page).then(function(result) {
                    var matchIndex = null,
                        newData = result[type];
                    for (var i = newData.length; i--;) {
                        if (newData[i].id === item.id) {
                            matchIndex = i;
                            break;
                        }
                    }
                    if (matchIndex === null) {
                        if (count > max) {
                            // Sanity check base case. If we have an issue with eventual consistency
                            // on the backend, let's not recurse forever.
                            defer.resolve([]);
                        } else {
                            newData = data.concat(newData);
                            queryUntilItem(service, type, item, newData, result.next_page, count+1).then(function (chainedResult) {
                                defer.resolve(chainedResult);
                            });
                        }
                    } else {
                        // base case
                        defer.resolve(newData.slice(0, matchIndex));
                    }
                });

                return defer.promise;
            }

            this.setLimit = function(limit) {
                _this.limit = limit;
            };

            this.initResourceArchive = function(type) {
                var archive = _this.resourceArchive[type];
                doQuery(archive.service).then(function(result) {
                    mungeResourceData(result[type], type);
                    archive.archive = result[type];
                    archive.next_page = result.next_page;
                    bumpVersion();
                }, function() {
                    // TODO: setting the resourceArchive to an empty array here will cause problems if
                    // any update fails, so we should probably have some way of indicating a failure,
                    // rather than setting it to an empty array.
                    archive.archive = [];
                });
            };

            this.updateResourceArchive = function(type) {
                var archive = _this.resourceArchive[type],
                    latestItem = archive.archive[0];
                queryUntilItem(archive.service, type, latestItem).then(function(newData) {
                    mungeResourceData(newData, type);
                    archive.archive = newData.concat(archive.archive);
                    bumpVersion();
                });
            };

            this.fetchMoreResourceArchive = function(type) {
                var archive = _this.resourceArchive[type];
                if (archive.next_page !== null) {
                    doQuery(archive.service, archive.next_page).then(function(result) {
                        mungeResourceData(result[type], type);
                        archive.archive = archive.archive.concat(result[type]);
                        archive.next_page = result.next_page;
                        bumpVersion();
                    });
                }
            };

            this.getResourceArchive = function() {
                return _this.resourceArchive;
            };

            this.getResourceArchiveVersion = function() {
                return _this.resourceArchiveVersion;
            };

            this.hasNext = function(type) {
                return _this.resourceArchive[type].next_page !== null;
            };

    }])

    ;

})(window.angular);
