(function(angular) {
    'use strict';

    angular.module('confidant.resources.controllers.ResourceCtrl', [
        'ui.router',
        'ngResource',
        'xeditable',
        'confidant.resources.services'
    ])


    .controller('resources.ResourceCtrl', [
        '$scope',
        '$stateParams',
        '$q',
        '$log',
        'credentials.CredentialListService',
        'blindcredentials.BlindCredentialListService',
        'services.ServiceListService',
        function ($scope, $stateParams, $q, $log, CredentialListService, BlindCredentialListService, ServiceListService) {
            $scope.$log = $log;
            $scope.showDisabled = false;

            $scope.getCredentialList = CredentialListService.getCredentialList;
            $scope.$watch('getCredentialList()', function(newCredentialList, oldCredentialList) {
                if(newCredentialList !== oldCredentialList) {
                    $scope.credentialList = newCredentialList;
                }
            });
            $scope.$emit('updateCredentialList');

            $scope.getBlindCredentialList = BlindCredentialListService.getBlindCredentialList;
            $scope.$watch('getBlindCredentialList()', function(newBlindCredentialList, oldBlindCredentialList) {
                if(newBlindCredentialList !== oldBlindCredentialList) {
                    $scope.blindCredentialList = newBlindCredentialList;
                }
            });
            $scope.$emit('updateBlindCredentialList');

            $scope.getServiceList = ServiceListService.getServiceList;
            $scope.$watch('getServiceList()', function(newServiceList, oldServiceList) {
                if(newServiceList !== oldServiceList) {
                    $scope.serviceList = newServiceList;
                }
            });
            $scope.$emit('updateServiceList');

            $scope.resourceRegexFilter = function(field, regex) {
                return function(resource) {
                    var pattern = new RegExp(regex, 'ig');
                    return pattern.test(resource[field]);
                };
            };

        }])

    ;

})(window.angular);
