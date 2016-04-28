/**
 * common $resources for Confidant
 */
(function(angular) {
    'use strict';

    angular.module('confidant.resources.services.blindcredentials', [
        'ngResource',
        'confidant.common.constants'
    ])

    .factory('blindcredentials.list', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.BLIND_CREDENTIALS);
    }])

    .factory('blindcredentials.archiveList', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.BLIND_ARCHIVE_CREDENTIALS);
    }])

    .factory('blindcredentials.credential', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.BLIND_CREDENTIAL, {id: '@id'}, {
            update: {method: 'PUT', isArray: false}
        });
    }])

    .factory('blindcredentials.archiveCredentialRevisions', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.BLIND_ARCHIVE_CREDENTIAL_REVISIONS, {id: '@id'});
    }])

    .factory('blindcredentials.services', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.BLIND_CREDENTIAL_SERVICES, {id: '@id'});
    }])

    .service('blindcredentials.BlindCredentialListService', [
        '$rootScope',
        'blindcredentials.list',
        function($rootScope, BlindCredentialList) {
            var _this = this;
            this.blindCredentialList = [];
            $rootScope.$on('updateBlindCredentialList', function() {
                BlindCredentialList.get().$promise.then(function(blindCredentialList) {
                    _this.blindCredentialList = blindCredentialList.blind_credentials;
                });
            });

            this.getBlindCredentialList = function() {
                return _this.blindCredentialList;
            };

    }])

    ;

})(window.angular);
