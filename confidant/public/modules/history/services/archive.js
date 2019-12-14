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
            function doQuery(service) {
                var d = $q.defer(),
                    result = service.get(function() { d.resolve(result); });
                return d.promise;
            }
            var _this = this;
            this.resourceArchive = [];

            this.updateResourceArchive = function() {
                var credentialArchivePromise = doQuery(CredentialArchive),
                    blindCredentialArchivePromise = doQuery(BlindCredentialArchive),
                    serviceArchivePromise = doQuery(ServiceArchive);
                $q.all([credentialArchivePromise, blindCredentialArchivePromise, serviceArchivePromise]).then(function(results) {
                    var credentialArchive = results[0].credentials,
                        blindCredentialArchive = results[1].blind_credentials,
                        serviceArchive = results[2].services;
                    for (var i = credentialArchive.length; i--;) {
                        credentialArchive[i].type = 'credential';
                    }
                    for (i = blindCredentialArchive.length; i--;) {
                        blindCredentialArchive[i].type = 'blind_credential';
                    }
                    for (i = serviceArchive.length; i--;) {
                        serviceArchive[i].type = 'service';
                        var nameArr = serviceArchive[i].id.split('-');
                        nameArr.pop();
                        serviceArchive[i].name = nameArr.join('-');
                    }
                    _this.resourceArchive = credentialArchive.concat(blindCredentialArchive);
                    _this.resourceArchive = _this.resourceArchive.concat(serviceArchive);
                    _this.resourceArchive.forEach(function(resource){
                        resource.modified_date = new Date(resource.modified_date);
                    });
                }, function() {
                    _this.resourceArchive = [];
                });
            };

            this.getResourceArchive = function() {
                return _this.resourceArchive;
            };

    }])

    ;

})(window.angular);
