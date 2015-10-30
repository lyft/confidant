/**
 * Common constants
 *
 * An example common module that defines constants.
 */

(function(angular) {
    'use strict';

    angular.module('confidant.common.constants', [])

    .constant('CONFIDANT_URLS', {
        USEREMAIL: 'v1/user/email',
        DATAKEY: 'v1/datakey',
        SERVICE: 'v1/services/:id',
        SERVICES: 'v1/services',
        GRANTS: 'v1/grants/:id',
        ARCHIVE_SERVICES: 'v1/archive/services',
        ARCHIVE_SERVICE_REVISIONS: 'v1/archive/services/:id/:revision',
        CREDENTIAL: 'v1/credentials/:id',
        CREDENTIAL_SERVICES: 'v1/credentials/:id/services',
        CREDENTIALS: 'v1/credentials',
        ARCHIVE_CREDENTIALS: 'v1/archive/credentials',
        ARCHIVE_CREDENTIAL_REVISIONS: 'v1/archive/credentials/:id/:revision',
        ROLES: 'v1/roles'
    })

    .constant('common.APP_EVENTS', {
        START_REQUEST: 'START_REQUEST',
        END_REQUEST: 'END_REQUEST',
        SHOW_SPINNER: 'SHOW_SPINNER',
        HIDE_SPINNER: 'HIDE_SPINNER',
        STATE_READY: 'eventStateInitComplete'
    })

    ;

})(window.angular);
