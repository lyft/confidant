(function(angular) {
    'use strict';

    angular.module('confidant.history.controllers.ResourceHistoryCtrl', [
        'ui.router',
        'ngResource',
        'xeditable',
        'confidant.resources.services',
        'confidant.history.services'
    ])


    .controller('history.ResourceHistoryCtrl', [
        '$scope',
        '$log',
        '$location',
        'credentials.list',
        'blindcredentials.list',
        'history.ResourceArchiveService',
        function ($scope, $log, $location, CredentialList, BlindCredentialList, ResourceArchiveService) {
            $scope.showCredentials = true;
            $scope.showBlindCredentials = true;
            $scope.showServices = true;

            CredentialList.get().$promise.then(function(credentialList) {
                $scope.credentialList = credentialList.credentials;
            }, function() {
                $scope.credentialList = [];
            });

            BlindCredentialList.get().$promise.then(function(blindCredentialList) {
                $scope.blindCredentialList = blindCredentialList.blind_credentials;
            }, function() {
                $scope.blindCredentialList = [];
            });

            // Reformat archive credential IDs for display. Archive credential IDs
            // are formatted as id-revision.
            $scope.reformatId = function(id) {
                return id.split('-')[0];
            };

            $scope.resourceRegexFilter = function(field, regex) {
                return function(resource) {
                    var pattern = new RegExp(regex, 'ig');
                    return pattern.test(resource[field]);
                };
            };

            $scope.resourceTypeFilter = function(field) {
                return function(resource) {
                    if (resource[field] == 'credential' && $scope.showCredentials) {
                        return true;
                    } else if (resource[field] == 'blind_credential' && $scope.showBlindCredentials) {
                        return true;
                    } else if (resource[field] == 'service' && $scope.showServices) {
                        return true;
                    }
                    return false;
                };
            };

            $scope.gotoResource = function(resource) {
                if (resource.type === 'credential') {
                    $location.path('/history/credential/' + resource.id);
                } else if (resource.type === 'blind_credential') {
                    $location.path('/history/blind_credential/' + resource.id);
                } else if (resource.type === 'service') {
                    $location.path('/history/service/' + resource.id);
                }
            };

            $scope.$log = $log;
            $scope.getResourceArchive = ResourceArchiveService.getResourceArchive;
            $scope.$watch('getResourceArchive()', function(newResourceArchive, oldResourceArchive) {
                if(newResourceArchive !== oldResourceArchive) {
                    $scope.resourceArchive = newResourceArchive;
                }
            });
            ResourceArchiveService.updateResourceArchive();

        }])

    ;

})(window.angular);
