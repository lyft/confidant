(function(angular) {
'use strict';

    angular.module('confidantApp', [
        // external libs
        'ngAnimate',
        'ngCookies',
        'ngResource',
        'ngRoute',
        'ngSanitize',
        'ngTouch',
        'ui.bootstrap',

        // local dependencies
        'confidant.common',

        // load routes
        'confidant.routes'
    ])

    /*
     * Main controller
     */
    .controller('ConfidantMainCtrl', [
        '$scope', 'common.userinfo',
        function ConfidantMainCtrl($scope, userinfo) {

        $scope.user = userinfo.get();

    }])

    .config([
        '$httpProvider',
        function($httpProvider) {

        // Broadcast events when HTTP requests are made.
        $httpProvider.interceptors.push('common.HttpEventInterceptor');
    }])

    ;

})(window.angular);
