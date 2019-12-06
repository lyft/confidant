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
        SERVICE_METADATA: 'v1/services/:id/metadata',
        SERVICE_REVISION: 'v1/services/:id/:revision',
        SERVICES: 'v1/services',
        GRANTS: 'v1/grants/:id',
        ARCHIVE_SERVICES: 'v1/archive/services',
        ARCHIVE_SERVICE_REVISIONS: 'v1/archive/services/:id/:revision',
        CREDENTIAL: 'v1/credentials/:id',
        CREDENTIAL_SERVICES: 'v1/credentials/:id/services',
        CREDENTIALS: 'v1/credentials',
        ARCHIVE_CREDENTIALS: 'v1/archive/credentials',
        ARCHIVE_CREDENTIAL_REVISIONS: 'v1/archive/credentials/:id/:revision',
        BLIND_CREDENTIAL: 'v1/blind_credentials/:id',
        BLIND_CREDENTIAL_SERVICES: 'v1/blind_credentials/:id/services',
        BLIND_CREDENTIALS: 'v1/blind_credentials',
        BLIND_ARCHIVE_CREDENTIALS: 'v1/archive/blind_credentials',
        BLIND_ARCHIVE_CREDENTIAL_REVISIONS: 'v1/archive/blind_credentials/:id/:revision',
        ROLES: 'v1/roles',
        VALUE_GENERATOR: 'v1/value_generator',
        CLIENT_CONFIG: 'v1/client_config'
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
