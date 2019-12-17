(function(angular) {
    'use strict';

    angular.module('confidant.history.controllers.CredentialHistoryCtrl', [
        'ui.router',
        'ngResource',
        'xeditable',
        'confidant.resources.services',
        'confidant.history.services'
    ])


    .controller('history.CredentialHistoryCtrl', [
        '$scope',
        '$stateParams',
        '$filter',
        '$q',
        '$log',
        '$location',
        'credentials.credential',
        'credentials.credentialDiff',
        'credentials.archiveCredentialRevisions',
        'history.ResourceArchiveService',
        function ($scope, $stateParams, $filter, $q, $log, $location, Credential, CredentialDiff, CredentialArchiveRevisions, ResourceArchiveService) {
            $scope.$log = $log;
            $scope.revisions = [];
            $scope.getError = '';
            $scope.saveError = '';
            $scope.noDiff = false;
            // TODO: set this from the return value
            $scope.hasDiff = true;

            var idArr = $stateParams.credentialId.split('-');
            $scope.credentialRevision = parseInt(idArr.pop(), 10);
            $scope.credentialId = idArr.join('-');
            CredentialArchiveRevisions.get({'id': $scope.credentialId}).$promise.then(function(revisions) {
                $scope.revisions = $filter('orderBy')(revisions.revisions, 'revision', true);
                $scope.currentRevision = parseInt($scope.revisions[0].revision, 10);
                $scope.currentCredential = $scope.revisions[0];
                $scope.isOnlyRevision = false;
                $scope.isCurrentRevision = false;
                if ($scope.currentRevision === 1) {
                    $scope.isOnlyRevision = true;
                } else {
                    if ($scope.credentialRevision === $scope.currentRevision) {
                        $scope.diffRevision = $scope.currentRevision - 1;
                        $location.path('/history/credential/' + $scope.credentialId + '-' + $scope.diffRevision);
                    } else {
                        $scope.diffRevision = $scope.credentialRevision;
                    }
                    CredentialDiff.get({'id': $scope.credentialId, 'old_revision': $scope.diffRevision, 'new_revision': $scope.currentRevision}).$promise.then(function(diff) {
                        $scope.diff = diff;
                        if (angular.equals({}, diff)) {
                            $scope.noDiff = true;
                        }
                    }, function(res) {
                        $scope.getError = res.data.error;
                    });
                }
                if ($scope.currentRevision === $scope.credentialRevision) {
                    $scope.isCurrentRevision = true;
                }
            });

            $scope.getCredentialByID = function(id, revision) {
                return $filter('filter')($scope.$parent.credentialList, {'id': id, 'revision': revision})[0];
            };

            $scope.getBlindCredentialByID = function(id, revision) {
                return $filter('filter')($scope.$parent.blindCredentialList, {'id': id, 'revision': revision})[0];
            };

            $scope.isString = function(value) {
                return angular.isString(value);
            };

            $scope.revertToDiffRevision = function() {
                var deferred = $q.defer();
                Credential.revert({'id': $scope.credentialId, revision: $scope.diffRevision}).$promise.then(function(newCredential) {
                    deferred.resolve();
                    ResourceArchiveService.updateResourceArchive();
                    $location.path('/history/credential/' + newCredential.id + '-' + newCredential.revision);
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

})(window.angular);
