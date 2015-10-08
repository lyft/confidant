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
     * Email address for currently logged-in user.
     */
    .factory('common.userinfo', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.USEREMAIL);
    }])

    ;

})(window.angular);
