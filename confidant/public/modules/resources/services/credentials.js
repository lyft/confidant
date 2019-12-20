/**
 * common $resources for Confidant
 */
(function(angular) {
    'use strict';

    angular.module('confidant.resources.services.credentials', [
        'ngResource',
        'confidant.common.constants'
    ])

    .factory('credentials.list', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.CREDENTIALS);
    }])

    .factory('credentials.archiveList', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.ARCHIVE_CREDENTIALS, {page: '@page', revision: '@revision'});
    }])

    .factory('credentials.credential', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.CREDENTIAL, {id: '@id', revision: '@revision'}, {
            update: {method: 'PUT', isArray: false},
            revert: {method: 'PUT', isArray: false, url: CONFIDANT_URLS.CREDENTIAL_REVISION}
        });
    }])

    .factory('credentials.credentialDiff', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.CREDENTIAL_DIFF, {id: '@id', old_revision: '@old_revision', new_revision: '@new_revision'});
    }])

    .factory('credentials.archiveCredentialRevisions', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.ARCHIVE_CREDENTIAL_REVISIONS, {id: '@id'});
    }])

    .factory('credentials.services', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.CREDENTIAL_SERVICES, {id: '@id'});
    }])

    .factory('credentials.credentials', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.CREDENTIALS, {}, {
            create: {method: 'POST', isArray: false}
        });
    }])

    .factory('credentials.valueGenerator', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.VALUE_GENERATOR);
    }])

    .service('credentials.CredentialListService', [
        '$rootScope',
        'credentials.list',
        function($rootScope, CredentialList) {
            var _this = this;
            this.credentialList = [];
            $rootScope.$on('updateCredentialList', function() {
                CredentialList.get().$promise.then(function(credentialList) {
                    _this.credentialList = credentialList.credentials;
                });
            });

            this.getCredentialList = function() {
                return _this.credentialList;
            };

    }])

    ;

})(window.angular);
