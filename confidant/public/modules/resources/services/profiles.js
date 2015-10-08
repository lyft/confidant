/**
 * common $resources for Confidant
 */
(function(angular) {
    'use strict';

    angular.module('confidant.resources.services.profiles', [
        'ngResource',
        'confidant.common.constants'
    ])

    .factory('profiles.list', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.PROFILES);
    }])

    ;

})(window.angular);
