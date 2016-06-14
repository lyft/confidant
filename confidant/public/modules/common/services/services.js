(function(angular) {
    'use strict';


    /**
     * This module requires all common services.
     *
     * It mainly provides a convenient way to import all common services by only
     * requiring a dependency on a single module.
     *
     */
    angular.module('confidant.common.services', [
        // Keep this list sorted alphabetically!
        'confidant.common.services.clientconfig',
        'confidant.common.services.http',
        'confidant.common.services.NavService',
        'confidant.common.services.SpinOn',
        'confidant.common.services.userinfo'
    ])
    ;
}(angular));
