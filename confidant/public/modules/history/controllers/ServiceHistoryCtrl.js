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
        'services.serviceDiff',
        'services.archiveServiceRevisions',
        'history.ResourceArchiveService',
        function ($scope, $stateParams, $filter, $q, $log, $location, Service, ServiceDiff, ServiceArchiveRevisions, ResourceArchiveService) {
            $scope.$log = $log;
            $scope.revisions = [];
            $scope.getError = '';
            $scope.saveError = '';
            $scope.noDiff = false;
            // TODO: set this from the return value
            $scope.hasDiff = true;

            var idArr = $stateParams.serviceId.split('-');
            $scope.serviceRevision = parseInt(idArr.pop(), 10);
            $scope.serviceId = idArr.join('-');
            ServiceArchiveRevisions.get({'id': $scope.serviceId}).$promise.then(function(revisions) {
                $scope.revisions = $filter('orderBy')(revisions.revisions, 'revision', true);
                $scope.currentRevision = parseInt($scope.revisions[0].revision, 10);
                $scope.currentService = $scope.revisions[0];
                $scope.isOnlyRevision = false;
                if ($scope.currentRevision === 1) {
                    $scope.isOnlyRevision = true;
                } else {
                    if ($scope.serviceRevision === $scope.currentRevision) {
                        $scope.diffRevision = $scope.currentRevision - 1;
                        $location.path('/history/services/' + $scope.serviceId + '-' + $scope.diffRevision);
                    } else {
                        $scope.diffRevision = $scope.serviceRevision;
                    }
                    ServiceDiff.get({'id': $scope.serviceId, 'old_revision': $scope.diffRevision, 'new_revision': $scope.currentRevision}).$promise.then(function(diff) {
                        $scope.diff = diff;
                        if (angular.equals({}, diff)) {
                            $scope.noDiff = true;
                        }
                    }, function(res) {
                        $scope.getError = res.data.error;
                    });
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
                if (!name) {
                    name = credId + ' (archived?)';
                }
                return name;
            };

            $scope.getBlindCredentialName = function(credId) {
                var name = '';
                if (!$scope.$parent.blindCredentialList) {
                    return name;
                }
                name = _.result(_.find($scope.$parent.blindCredentialList, function(cred) {
                    return cred.id.indexOf(credId) === 0;
                }), 'name');
                return name;
            };

            $scope.getResourceValue = function(key, value) {
                if (key === 'credentials') {
                    return $scope.getCredentialName(value);
                } else if (key === 'blind_credentials') {
                    return $scope.getBlindCredentialName(value);
                } else {
                    return value;
                }
            };

            $scope.shouldDisplayList = function(value) {
                if (typeof value === 'string') {
                    return false;
                } else if (typeof value === 'boolean') {
                    return false;
                } else {
                    return true;
                }
            };

            $scope.revertToDiffRevision = function() {
                var deferred = $q.defer();
                Service.revert({'id': $scope.serviceId, revision: $scope.diffRevision}).$promise.then(function(newService) {
                    deferred.resolve();
                    ResourceArchiveService.updateResourceArchive('services');
                    $location.path('/history/services/' + newService.id + '-' + newService.revision);
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
