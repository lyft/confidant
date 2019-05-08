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
        '$scope', '$http', 'common.userinfo', 'common.userrole', 'common.clientconfig',
        function ConfidantMainCtrl($scope, $http, userinfo, userrole, clientconfig) {

        $scope.user = userinfo.get();
        $scope.role = userrole.get();
        clientconfig.get().$promise.then(function(clientConfig) {
            $scope.clientconfig = clientConfig;
            $http.defaults.xsrfCookieName = clientConfig.generated.xsrf_cookie_name;
        });

    }])

    .config([
        '$httpProvider',
        '$compileProvider',
        function($httpProvider, $compileProvider) {

        // Broadcast events when HTTP requests are made.
        $httpProvider.interceptors.push('common.HttpEventInterceptor');

        $compileProvider.debugInfoEnabled(false);
    }])

    ;

})(window.angular);
