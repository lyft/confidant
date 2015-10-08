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
        'services.archiveList',
        function($q, CredentialArchive, ServiceArchive) {
            function doQuery(service) {
                var d = $q.defer(),
                    result = service.get(function() { d.resolve(result); });
                return d.promise;
            }
            var _this = this;
            this.resourceArchive = [];

            this.updateResourceArchive = function() {
                var credentialArchivePromise = doQuery(CredentialArchive),
                    serviceArchivePromise = doQuery(ServiceArchive);
                $q.all([credentialArchivePromise, serviceArchivePromise]).then(function(results) {
                    var credentialArchive = results[0].credentials,
                        serviceArchive = results[1].services;
                    for (var i = credentialArchive.length; i--;) {
                        credentialArchive[i].type = 'credential';
                    }
                    for (i = serviceArchive.length; i--;) {
                        serviceArchive[i].type = 'service';
                        var nameArr = serviceArchive[i].id.split('-');
                        nameArr.pop();
                        serviceArchive[i].name = nameArr.join('-');
                    }
                    _this.resourceArchive = credentialArchive.concat(serviceArchive);
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
