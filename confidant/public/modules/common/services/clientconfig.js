/**
 * common $resources for Confidant
 */
(function(angular) {
    'use strict';

    angular.module('confidant.common.services.clientconfig', [
        'ngResource',
        'confidant.common.constants'
    ])

    /**
     * Client configuration provided by server.
     */
    .factory('common.clientconfig', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.CLIENT_CONFIG);
    }])

    ;

})(window.angular);
