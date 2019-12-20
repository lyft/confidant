(function(angular) {
    'use strict';

    angular.module('confidant.routes.history', [
        'ui.router',
        'confidant.history'
    ])

    .config(['$stateProvider', function($stateProvider) {
        $stateProvider

        .state('history', {
            url: '/history',
            views: {
                main: {
                    controller: 'history.ResourceHistoryCtrl',
                    templateUrl: '/modules/history/views/resources.html'
                }
            },
            data: {
                viewLocation: 'history'
            }
        })

        .state('history.credential-history', {
            url: '/credentials/:credentialId',
            views: {
                'details': {
                    controller: 'history.CredentialHistoryCtrl',
                    templateUrl: '/modules/history/views/credential-history.html'
                }
            },
            data: {
                viewLocation: 'history',
            }
        })

        .state('history.blind-credential-history', {
            url: '/blind_credentials/:blindCredentialId',
            views: {
                'details': {
                    controller: 'history.BlindCredentialHistoryCtrl',
                    templateUrl: '/modules/history/views/blind-credential-history.html'
                }
            },
            data: {
                viewLocation: 'history',
            }
        })

        .state('history.service-history', {
            url: '/services/:serviceId',
            views: {
                'details': {
                    controller: 'history.ServiceHistoryCtrl',
                    templateUrl: '/modules/history/views/service-history.html'
                }
            },
            data: {
                viewLocation: 'history',
            }
        })

        ;
    }])

    ;
}(window.angular));
