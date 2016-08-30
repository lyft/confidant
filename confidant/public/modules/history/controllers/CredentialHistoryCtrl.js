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
        'credentials.archiveCredentialRevisions',
        'history.ResourceArchiveService',
        function ($scope, $stateParams, $filter, $q, $log, $location, Credential, CredentialArchiveRevisions, ResourceArchiveService) {
            function doQuery(credential, id) {
                var d = $q.defer(),
                    result = credential.get({'id': id}, function() { d.resolve(result); });
                return d.promise;
            }

            $scope.$log = $log;
            $scope.revisions = [];

            var idArr = $stateParams.credentialId.split('-');
            $scope.credentialRevision = parseInt(idArr.pop(), 10);
            $scope.credentialId = idArr.join('-');
            CredentialArchiveRevisions.get({'id': $scope.credentialId}).$promise.then(function(revisions) {
                $scope.revisions = $filter('orderBy')(revisions.revisions, 'revision', true);
                $scope.currentRevision = parseInt($scope.revisions[0].revision, 10);
                $scope.isOnlyRevision = false;
                $scope.isCurrentRevision = false;
                if ($scope.currentRevision === 1) {
                    $scope.isOnlyRevision = true;
                    $scope.diffRevision = $scope.currentRevision;
                    Credential.get({'id': $stateParams.credentialId}).$promise.then(function(credential) {
                        $scope.currentCredential = credential;
                        $scope.diffCredential = credential;
                    }, function() {
                        $scope.currentCredential = null;
                        $scope.diffCredential = null;
                    });
                } else {
                    if ($scope.credentialRevision === $scope.currentRevision) {
                        $scope.diffRevision = $scope.currentRevision - 1;
                    } else {
                        $scope.diffRevision = $scope.credentialRevision;
                    }
                    var currentCredentialPromise = doQuery(Credential, $scope.credentialId + '-' + $scope.currentRevision),
                        diffCredentialPromise = doQuery(Credential, $scope.credentialId + '-' + $scope.diffRevision);
                    $q.all([currentCredentialPromise, diffCredentialPromise]).then(function(results) {
                        $scope.currentCredential = results[0];
                        $scope.diffCredential = results[1];
                    }, function() {
                        $scope.currentCredential = null;
                        $scope.diffCredential = null;
                    });
                }
                if ($scope.currentRevision === $scope.credentialRevision) {
                    $scope.isCurrentRevision = true;
                }
            });

            $scope.revertToDiffRevision = function() {
                var deferred = $q.defer();
                if (angular.equals($scope.diffCredential.name, $scope.currentCredential.name) &&
                    angular.equals($scope.diffCredential.credential_pairs, $scope.currentCredential.credential_pairs) &&
                    angular.equals($scope.diffCredential.metadata, $scope.currentCredential.metadata) &&
                    angular.equals($scope.diffCredential.enabled, $scope.currentCredential.enabled)) {
                    $scope.saveError = 'Can not revert to revision ' + $scope.diffCredential.revision + '. No difference between it and current revision.';
                    deferred.reject();
                    return deferred.promise;
                }
                Credential.update({'id': $scope.credentialId}, $scope.diffCredential).$promise.then(function(newCredential) {
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
