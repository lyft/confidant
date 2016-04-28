(function(angular) {
    'use strict';

    angular.module('confidant.resources.controllers.BlindCredentialDocsCtrl', [
        'ngResource',
        'confidant.resources.services'
    ])

    .controller('resources.BlindCredentialDocsCtrl', [
        '$scope',
        '$stateParams',
        '$log',
        'blindcredentials.credential',
        function ($scope, $stateParams, $log, BlindCredential) {
            $scope.$log = $log;

            BlindCredential.get({'id': $stateParams.blindCredentialId}).$promise.then(function(blindCredential) {
                $scope.blindCredential = blindCredential;
            });

        }])

    ;

})(window.angular);
