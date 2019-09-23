/**
 * common $resources for Confidant
 */
(function(angular) {
    'use strict';

    angular.module('confidant.common.services.userinfo', [
        'ngResource',
        'confidant.common.constants'
    ])

    /**
     * User info for currently logged-in user.
     */
    .factory('common.userinfo', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.USERINFO);
     }]);

})(window.angular);
