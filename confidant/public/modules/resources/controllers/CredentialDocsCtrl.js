(function(angular) {
    'use strict';

    angular.module('confidant.resources.controllers.CredentialDocsCtrl', [
        'ngResource',
        'confidant.resources.services'
    ])

    .controller('resources.CredentialDocsCtrl', [
        '$scope',
        '$stateParams',
        '$log',
        'credentials.credential',
        function ($scope, $stateParams, $log, Credential) {
            $scope.$log = $log;

            Credential.get({'id': $stateParams.credentialId}).$promise.then(function(credential) {
                var _credentialPairKeys = [];
                angular.forEach(credential.credential_pairs, function(value, key) {
                    this.push(key);
                }, _credentialPairKeys);
                $scope.credentialPairKeys = _credentialPairKeys;
            });

        }])

    ;

})(window.angular);
