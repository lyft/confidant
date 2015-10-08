(function(angular) {
    'use strict';

    angular.module('confidant.routes.resources', [
        'ui.router',
        'ui.bootstrap',
        'confidant.resources'
    ])

    .config(['$stateProvider', function($stateProvider) {
        $stateProvider

        .state('resources', {
            url: '/resources',
            views: {
                main: {
                    controller: 'resources.ResourceCtrl',
                    templateUrl: '/modules/resources/views/resources.html'
                }
            },
            data: {
                viewLocation: 'resources'
            }
        })

        .state('resources.newCredential', {
            url: '/new/credential',
            views: {
                'details': {
                    controller: 'resources.CredentialDetailsCtrl',
                    templateUrl: '/modules/resources/views/credential-details.html'
                }
            },
            data: {
                viewLocation: 'resources'
            }
        })

        .state('resources.newService', {
            url: '/new/service',
            views: {
                'details': {
                    controller: 'resources.ServiceDetailsCtrl',
                    templateUrl: '/modules/resources/views/service-details.html'
                }
            },
            data: {
                viewLocation: 'resources'
            }
        })

        .state('resources.credential-details', {
            url: '/credential/:credentialId',
            views: {
                'details': {
                    controller: 'resources.CredentialDetailsCtrl',
                    templateUrl: '/modules/resources/views/credential-details.html'
                },
                'docs': {
                    controller: 'resources.CredentialDocsCtrl',
                    templateUrl: '/custom/modules/resources/views/credential-docs.html'
                }
            },
            data: {
                viewLocation: 'resources',
            }
        })

        .state('resources.service-details', {
            url: '/service/:serviceId',
            views: {
                'details': {
                    controller: 'resources.ServiceDetailsCtrl',
                    templateUrl: '/modules/resources/views/service-details.html'
                }
            },
            data: {
                viewLocation: 'resources',
            }
        })

        ;
    }])

    ;
}(window.angular));
