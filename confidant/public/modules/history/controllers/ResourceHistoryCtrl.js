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
        '$timeout',
        '$location',
        '$filter',
        'credentials.list',
        'blindcredentials.list',
        'history.ResourceArchiveService',
        function ($scope, $log, $timeout, $location, $filter, CredentialList, BlindCredentialList, ResourceArchiveService) {
            $scope.typeFilter = 'credentials';

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

            $scope.getCredentialByID = function(id) {
                return $filter('filter')($scope.credentialList, {'id': id})[0];
            };

            $scope.getBlindCredentialByID = function(id) {
                return $filter('filter')($scope.blindCredentialList, {'id': id})[0];
            };

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
                    if (resource[field] === $scope.typeFilter) {
                        return true;
                    }
                    return false;
                };
            };

            $scope.setTypeFilter = function(type) {
                $scope.typeFilter = type;
            };

            $scope.gotoResource = function(resource) {
                $location.path('/history/' + resource.type + '/' + resource.id);
            };


            $scope.$log = $log;
            $scope.hasNext = ResourceArchiveService.hasNext;
            $scope.fetchMoreResourceArchive = ResourceArchiveService.fetchMoreResourceArchive;
            $scope.getResourceArchive = ResourceArchiveService.getResourceArchive;
            $scope.getResourceArchiveVersion = ResourceArchiveService.getResourceArchiveVersion;
            $scope.$watch('getResourceArchiveVersion()', function(newVersion, oldVersion) {
                if(newVersion !== oldVersion) {
                    $scope.resourceArchive = ResourceArchiveService.getResourceArchive();
                }
            });
            // TODO: There's a race condition here, for some reason. We need to figure out how to
            // wait until the clientconfig is loaded before calling this. For now we're using a gross
            // timeout hack. client_config endpoint is fast, so it's very likely it'll be loaded within
            // the time period
            if (angular.isUndefined($scope.clientconfig)) {
                $timeout(function() {
                    ResourceArchiveService.setLimit($scope.clientconfig.generated.history_page_limit);
                    ResourceArchiveService.initResourceArchive('credentials');
                    ResourceArchiveService.initResourceArchive('blind_credentials');
                    ResourceArchiveService.initResourceArchive('services');
                }, 1000);
            } else {
                // When moving between resources and history, the client config already exists, so we
                // can avoid the timeout.
                ResourceArchiveService.setLimit($scope.clientconfig.generated.history_page_limit);
                ResourceArchiveService.initResourceArchive('credentials');
                ResourceArchiveService.initResourceArchive('blind_credentials');
                ResourceArchiveService.initResourceArchive('services');
            }

        }])

    ;

})(window.angular);
