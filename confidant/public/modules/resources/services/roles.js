/**
 * common $resources for Confidant
 */
(function(angular) {
    'use strict';

    angular.module('confidant.resources.services.roles', [
        'ngResource',
        'confidant.common.constants'
    ])

    .factory('roles.list', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.ROLES);
    }])

    ;

})(window.angular);
