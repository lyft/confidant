(function(angular) {
    'use strict';

    angular.module('confidant.resources.controllers.BlindCredentialDetailsCtrl', [
        'ui.router',
        'ngResource',
        'xeditable',
        'confidant.resources.services'
    ])


    .controller('resources.BlindCredentialDetailsCtrl', [
        '$scope',
        '$stateParams',
        '$q',
        '$log',
        '$filter',
        '$location',
        'blindcredentials.credential',
        'blindcredentials.services',
        function ($scope, $stateParams, $q, $log, $filter, $location, BlindCredential, BlindCredentialServices) {
            $scope.$log = $log;

            if ($stateParams.blindCredentialId) {
                BlindCredentialServices.get({'id': $stateParams.blindCredentialId}).$promise.then(function(blindCredentialServices) {
                    $scope.blindCredentialServices = blindCredentialServices.services;
                });

                BlindCredential.get({'id': $stateParams.blindCredentialId}).$promise.then(function(blindCredential) {
                    $scope.blindCredential = blindCredential;
                    $scope.shown = false;
                });
            } else {
                $scope.blindCredential = {
                    name: '',
                    enabled: true
                };
                $scope.shown = true;
            }

            // TODO: add ability to save/cancel

        }])

    ;
})(window.angular);
