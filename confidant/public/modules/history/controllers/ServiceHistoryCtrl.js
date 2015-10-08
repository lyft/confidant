(function(angular, _) {
    'use strict';

    angular.module('confidant.history.controllers.ServiceHistoryCtrl', [
        'ui.router',
        'ngResource',
        'xeditable',
        'confidant.resources.services',
        'confidant.history.services'
    ])


    .controller('history.ServiceHistoryCtrl', [
        '$scope',
        '$stateParams',
        '$filter',
        '$q',
        '$log',
        '$location',
        'services.service',
        'services.archiveServiceRevisions',
        'history.ResourceArchiveService',
        function ($scope, $stateParams, $filter, $q, $log, $location, Service, ServiceArchiveRevisions, ResourceArchiveService) {
            $scope.$log = $log;
            $scope.revisions = [];

            var idArr = $stateParams.serviceId.split('-');
            $scope.serviceRevision = parseInt(idArr.pop(), 10);
            $scope.serviceId = idArr.join('-');
            ServiceArchiveRevisions.get({'id': $scope.serviceId}).$promise.then(function(revisions) {
                $scope.revisions = $filter('orderBy')(revisions.revisions, 'revision', true);
                $scope.currentRevision = parseInt($scope.revisions[0].revision, 10);
                if ($scope.currentRevision === 1) {
                    $scope.isOnlyRevision = true;
                    $scope.diffRevision = $scope.currentRevision;
                } else {
                    if ($scope.serviceRevision === $scope.currentRevision) {
                        $scope.diffRevision = $scope.currentRevision - 1;
                    } else {
                        $scope.diffRevision = $scope.serviceRevision;
                    }
                }
                if ($scope.currentRevision === $scope.serviceRevision) {
                    $scope.isCurrentRevision = true;
                }
            });

            $scope.getServiceByRevision = function(rev) {
                return $filter('filter')($scope.revisions, {revision: rev})[0];
            };

            $scope.getCredentialName = function(credId) {
                var name = '';
                if (!$scope.$parent.credentialList) {
                    return name;
                }
                name = _.result(_.find($scope.$parent.credentialList, function(cred) {
                    return cred.id.indexOf(credId) === 0;
                }), 'name');
                return name;
            };

            $scope.revertToDiffRevision = function() {
                var diffService = $scope.getServiceByRevision($scope.diffRevision),
                    currentService = $scope.getServiceByRevision($scope.currentRevision),
                    deferred = $q.defer();
                if (angular.equals(diffService.credentials, currentService.credentials) &&
                    angular.equals(diffService.enabled, currentService.enabled)) {
                    $scope.saveError = 'Can not revert to revision ' + diffService.revision + '. No difference between it and current revision.';
                    deferred.reject();
                    return deferred.promise;
                }
                Service.update({'id': $scope.serviceId}, diffService).$promise.then(function(newService) {
                    deferred.resolve();
                    ResourceArchiveService.updateResourceArchive();
                    $location.path('/history/service/' + newService.id + '-' + newService.revision);
                }, function(res) {
                    if (res.status === 500) {
                        $scope.saveError = 'Unexpected server error.';
                        $log.error(res);
                    } else {
                        $scope.saveError = res.data.error;
                        if ('conflicts' in res.data) {
                            $scope.credentialPairConflicts = res.data.conflicts;
                        }
                    }
                    deferred.reject();
                });
                return deferred.promise;
            };

        }])

    ;

})(window.angular, window._);
