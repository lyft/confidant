(function(angular) {
    'use strict';


    /**
     * This module requires all common services.
     *
     * It mainly provides a convenient way to import all common services by only
     * requiring a dependency on a single module.
     *
     */
    angular.module('confidant.resources.services', [
        // Keep this list sorted alphabetically!
        'confidant.resources.services.confidantservices',
        'confidant.resources.services.credentials',
        'confidant.resources.services.roles'
    ])
    ;
}(angular));
