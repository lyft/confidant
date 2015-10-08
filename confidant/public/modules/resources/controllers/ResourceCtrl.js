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
        'services.ServiceListService',
        function ($scope, $stateParams, $q, $log, CredentialListService, ServiceListService) {
            $scope.$log = $log;
            $scope.showDisabled = false;

            $scope.getCredentialList = CredentialListService.getCredentialList;
            $scope.$watch('getCredentialList()', function(newCredentialList, oldCredentialList) {
                if(newCredentialList !== oldCredentialList) {
                    $scope.credentialList = newCredentialList;
                }
            });
            $scope.$emit('updateCredentialList');

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
