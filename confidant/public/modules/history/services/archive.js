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
        '$q',
        'credentials.archiveList',
        'blindcredentials.archiveList',
        'services.archiveList',
        function($q, CredentialArchive, BlindCredentialArchive, ServiceArchive) {
            var _this = this;
            this.resourceArchive = [];
            this.credentialArchive = [];
            this.nextCredentialPage = null;
            this.blindCredentialArchive = [];
            this.nextBlindCredentialPage = null;
            this.serviceArchive = [];
            this.nextServicePage = null;
            this.limit = 1;

            function doQuery(service, page, limit) {
                limit = limit || _this.limit;
                page = page || null;
                return service.get({'page': page, 'limit': limit}).$promise.then(function(result) { return result; });
            }

            function concatArchives() {
                _this.resourceArchive = _this.credentialArchive
                    .concat(_this.blindCredentialArchive)
                    .concat(_this.serviceArchive);
            }

            function mungeResourceData(data, dataType) {
                data.forEach(function(resource){
                    resource.type = dataType;
                    resource.modified_date = new Date(resource.modified_date);
                    if (dataType === 'service') {
                        // For consistency, everything has a name, so we'll set the service name from its ID.
                        // The ID is name-revision, so we need to split and take the first item.
                        resource.name = resource.id.split('-')[0];
                    }
                });
            }

            this.setLimit = function(limit) {
                _this.limit = limit;
            };

            this.updateResourceArchive = function() {
                var credentialArchivePromise = doQuery(CredentialArchive),
                    blindCredentialArchivePromise = doQuery(BlindCredentialArchive),
                    serviceArchivePromise = doQuery(ServiceArchive);
                $q.all([credentialArchivePromise, blindCredentialArchivePromise, serviceArchivePromise]).then(function(results) {
                    var credentialArchive = results[0].credentials,
                        blindCredentialArchive = results[1].blind_credentials,
                        serviceArchive = results[2].services;
                    // We fetched each archive without a page set. We're either initializing them for the view,
                    // or a change has occurred and we're fetching data and pushing it onto the top of the archives.
                    // Initialization is occurring if the archive is empty. If we're pushing data on the top,
                    // we need to ensure we fetch all new data, or we'll be missing data in the view. For that we'll
                    // need to page until we hit the first record of the archive.
                    mungeResourceData(credentialArchive, 'credential');
                    if (_this.credentialArchive.length === 0) {
                        _this.credentialArchive = credentialArchive;
                        _this.nextCredentialPage = results[0].next_page;
                    } else {
                        // TODO: take top item in this.credentialArchive, find the index in the fetched
                        // version and splice them together at that point. If it's not found, fetch another
                        // page of the credentials.
                    }
                    mungeResourceData(blindCredentialArchive, 'blind_credential');
                    if (_this.blindCredentialArchive.length === 0) {
                        _this.blindCredentialArchive = blindCredentialArchive;
                        _this.nextBlindCredentialPage = results[1].next_page;
                    } else {
                        // TODO: take top item in this.blindCredentialArchive, find the index in the fetched
                        // version and splice them together at that point. If it's not found, fetch another
                        // page of the blind credentials.
                    }
                    mungeResourceData(serviceArchive, 'service');
                    if (_this.serviceArchive.length === 0) {
                        _this.serviceArchive = serviceArchive;
                        _this.nextServicePage = results[2].next_page;
                    } else {
                        // TODO: take top item in this.serviceArchive, find the index in the fetched
                        // version and splice them together at that point. If it's not found, fetch another
                        // page of the services.
                    }
                    concatArchives();
                }, function() {
                    // TODO: setting the resourceArchive to an empty array here will cause problems if
                    // any update fails, so we should probably have some way of indicating a failure,
                    // rather than setting it to an empty array.
                    _this.resourceArchive = [];
                });
            };

            this.fetchMoreResourceArchive = function() {
                var promises = [];
                if (_this.nextCredentialPage !== null) {
                    promises.push(doQuery(CredentialArchive, _this.nextCredentialPage));
                }
                if (_this.nextBlindCredentialPage !== null) {
                    promises.push(doQuery(BlindCredentialArchive, _this.nextBlindCredentialPage));
                }
                if (_this.nextServicePage !== null) {
                    promises.push(doQuery(ServiceArchive, _this.nextServicePage));
                }
                $q.all(promises).then(function(results) {
                    var credentialArchive = [],
                        blindCredentialArchive = [],
                        serviceArchive = [];
                    for (var i = results.length; i--;) {
                        if (angular.isDefined(results[i].credentials)) {
                            credentialArchive = results[i].credentials;
                            _this.nextCredentialPage = results[i].next_page;
                        } else if (angular.isDefined(results[i].blind_credentials)) {
                            blindCredentialArchive = results[i].blind_credentials;
                            _this.nextBlindCredentialPage = results[i].next_page;
                        } else if (angular.isDefined(results[i].services)) {
                            serviceArchive = results[i].services;
                            _this.nextServicePage = results[i].next_page;
                        }
                    }
                    mungeResourceData(credentialArchive, 'credential');
                    _this.credentialArchive = _this.credentialArchive.concat(credentialArchive);
                    mungeResourceData(blindCredentialArchive, 'blind_credential');
                    _this.blindCredentialArchive = _this.blindCredentialArchive.concat(blindCredentialArchive);
                    mungeResourceData(serviceArchive, 'service');
                    _this.serviceArchive = _this.serviceArchive.concat(serviceArchive);
                    concatArchives();
                });
            };

            this.getResourceArchive = function() {
                return _this.resourceArchive;
            };

            this.hasNext = function(type) {
                if (type === 'credential') {
                    return _this.nextCredentialPage !== null;
                } else if (type === 'blind-credential') {
                    return _this.nextBlindCredentialPage !== null;
                } else if (type === 'service') {
                    return _this.nextServicePage !== null;
                }
            };

    }])

    ;

})(window.angular);
