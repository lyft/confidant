(function(angular) {
    'use strict';

    /**
     * This module requires all routes.
     *
     * The main app depends on this module, which provides a convenient way to
     * import all routes. Each route module in turn depends on the module or
     * modules that contain its controllers, services and directives.
     *
     * Be sure to add your route module below when adding new pages.
     */
    angular.module('confidant.routes', [
        // Keep this list alphabetized!
        'confidant.routes.history',
        'confidant.routes.resources'
    ])

    .config([
        '$urlRouterProvider',
        function($urlRouterProvider) {
            // default url
            $urlRouterProvider.otherwise('/resources');
        }])

    ;
}(window.angular));
