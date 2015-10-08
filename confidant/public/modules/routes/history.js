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
            url: '/credential/:credentialId',
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

        .state('history.service-history', {
            url: '/service/:serviceId',
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
