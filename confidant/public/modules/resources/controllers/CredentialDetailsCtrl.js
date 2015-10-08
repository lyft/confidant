(function(angular) {
    'use strict';

    angular.module('confidant.resources.controllers.CredentialDetailsCtrl', [
        'ui.router',
        'ngResource',
        'xeditable',
        'confidant.resources.services'
    ])


    .directive('lowercase', function($parse) {
        return {
            require: 'ngModel',
            link: function(scope, element, attrs, modelCtrl) {
                var lowercase = function(inputValue) {
                    if (inputValue === undefined) {
                        inputValue = '';
                    }
                    var lowercased = angular.lowercase(inputValue);
                    if (lowercased !== inputValue) {
                        modelCtrl.$setViewValue(lowercased);
                        modelCtrl.$render();
                    }
                    return lowercased;
                };
                modelCtrl.$parsers.push(lowercase);
                lowercase($parse(attrs.ngModel)(scope));
            }
        };
    })

    .controller('resources.CredentialDetailsCtrl', [
        '$scope',
        '$stateParams',
        '$q',
        '$log',
        '$filter',
        '$location',
        'credentials.credential',
        'credentials.credentials',
        'credentials.services',
        function ($scope, $stateParams, $q, $log, $filter, $location, Credential, Credentials, CredentialServices) {
            var credentialCopy = null;
            $scope.$log = $log;
            $scope.saveError = '';
            $scope.credentialPairConflicts = null;

            if ($stateParams.credentialId) {
                CredentialServices.get({'id': $stateParams.credentialId}).$promise.then(function(credentialServices) {
                    $scope.credentialServices = credentialServices['services'];
                });

                Credential.get({'id': $stateParams.credentialId}).$promise.then(function(credential) {
                    var _credentialPairs = [];
                    angular.forEach(credential.credential_pairs, function(value, key) {
                        this.push({'key': key, 'value': value});
                    }, _credentialPairs);
                    credential.credentialPairs = _credentialPairs;
                    $scope.credential = credential;
                    credentialCopy = angular.copy($scope.credential);
                    $scope.shown = false;
                });
            } else {
                $scope.credential = {
                    name: '',
                    enabled: true,
                    credentialPairs: [{'key': '', 'value': ''}]
                };
                credentialCopy = angular.copy($scope.credential);
                $scope.shown = true;
            }

            $scope.showValue = function(credentialPair) {
                if (credentialPair.shown) {
                    return credentialPair.value;
                } else {
                    return '***************';
                }
            };

            $scope.toggleCredentialMask = function(credentialPair) {
                if (credentialPair.shown) {
                    credentialPair.shown = false;
                } else {
                    credentialPair.shown = true;
                }
            };

            $scope.filterCredentialPair = function(credentialPair) {
                return credentialPair.isDeleted !== true;
            };

            $scope.getCredentialByID = function(id) {
                return $filter('filter')($scope.$parent.credentialList, {'id': id})[0];
            };

            $scope.deleteCredentialPair = function($$hashKey) {
                var filtered = $filter('filter')($scope.credential.credentialPairs, {'$$hashKey': $$hashKey});
                if (filtered.length) {
                    filtered[0].isDeleted = true;
                }
            };

            $scope.addCredentialPair = function() {
                $scope.credential.credentialPairs.push({
                    key: '',
                    value: '',
                    isNew: true
                });
            };

            $scope.cancel = function() {
                $scope.credentialPairConflicts = null;
                $scope.saveError = '';
                $scope.credential = angular.copy(credentialCopy);
            };

            $scope.saveCredential = function() {
                var _credential = {},
                    deferred = $q.defer();
                $scope.credentialPairConflicts = null;
                _credential.name = $scope.credential.name;
                _credential.enabled = $scope.credential.enabled;
                _credential.credential_pairs = {};
                $scope.saveError = '';
                // Ensure credential pair keys are unique and transform them
                // into key/value dict.
                for (var i = $scope.credential.credentialPairs.length; i--;) {
                    var credentialPair = $scope.credential.credentialPairs[i];
                    if (credentialPair.isDeleted) {
                        $scope.credential.credentialPairs.splice(i, 1);
                        continue;
                    }
                    if (credentialPair.key in _credential.credential_pairs) {
                        $scope.saveError = 'Credential pair keys must be unique.';
                        return $scope.saveError;
                    }
                    _credential.credential_pairs[credentialPair.key] = credentialPair.value;
                }
                if (angular.equals(credentialCopy, $scope.credential)) {
                    $scope.saveError = 'No changes made.';
                    deferred.reject();
                    return deferred.promise;
                }
                // Update an existing credential.
                if ($scope.credential.id) {
                    Credential.update({'id': $scope.credential.id}, _credential).$promise.then(function(newCredential) {
                        var _credentialPairs = [];
                        angular.forEach(newCredential.credential_pairs, function(value, key) {
                            this.push({'key': key, 'value': value});
                        }, _credentialPairs);
                        newCredential.credentialPairs = _credentialPairs;
                        $scope.credential = newCredential;
                        if (credentialCopy.name !== $scope.credential.name ||
                            credentialCopy.enabled != $scope.credential.enabled) {
                            $scope.$emit('updateCredentialList');
                        }
                        credentialCopy = angular.copy(newCredential);
                        deferred.resolve();
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
                // Create a new credential.
                } else {
                    Credentials.create(_credential).$promise.then(function(newCredential) {
                        $scope.$emit('updateCredentialList');
                        deferred.resolve();
                        $location.path('/resources/credential/' + newCredential.id);
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
                }

                return deferred.promise;
            };

        }])

    ;
})(window.angular);
