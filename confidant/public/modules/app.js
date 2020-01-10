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
        '$scope', '$http', 'common.userinfo', 'common.clientconfig', '$log', '$transitions',
        function ConfidantMainCtrl($scope, $http, userinfo, clientconfig, $log, $transitions) {

        // Load the clientconfig prior to transitioning to any module, as most modules require
        // the clientconfig to load, and will fail otherwise.
        $transitions.onBefore({}, function(transition) {
          $scope.user = userinfo.get();
          return clientconfig.get().$promise.then(function(clientConfig) {
              $scope.clientconfig = clientConfig;
              $http.defaults.xsrfCookieName = clientConfig.generated.xsrf_cookie_name;
          });
        });

        // Update the view location after a successful move between modules
        $transitions.onSuccess({}, function(transition) {
          $scope.viewLocation = transition.to().data.viewLocation;
        });

    }])

    .config([
        '$httpProvider',
        '$compileProvider',
        '$locationProvider',
        function($httpProvider, $compileProvider, $locationProvider) {

        // Broadcast events when HTTP requests are made.
        $httpProvider.interceptors.push('common.HttpEventInterceptor');

        $compileProvider.debugInfoEnabled(false);

        // the location hashprefix was changed from '' to '!' in angular 1.6. Set it back for compat.
        $locationProvider.hashPrefix('');

        // lowercase was removed, but there's a $$lowercase function we can use for backwards compat.
        angular.lowercase = angular.$$lowercase;
    }])

    ;

})(window.angular);
