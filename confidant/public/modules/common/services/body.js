(function(angular) {
    'use strict';

    angular.module('confidant.common.services.$body', [])

    /**
     * Simple wrapper around $(document.body).
     */
    .service('$body', ['$document', function($document) {
        return $document.find('body');
    }])
    ;
}(window.angular));
