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
        'history.ResourceArchiveService',
        function ($scope, $log, $location, CredentialList, ResourceArchiveService) {
            CredentialList.get().$promise.then(function(credentialList) {
                $scope.credentialList = credentialList.credentials;
            }, function() {
                $scope.credentialList = [];
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

            $scope.gotoResource = function(resource) {
                if (resource.type === 'credential') {
                    $location.path('/history/credential/' + resource.id);
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
