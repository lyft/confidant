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
        'credentials.valueGenerator',
        function ($scope, $stateParams, $q, $log, $filter, $location, Credential, Credentials, CredentialServices, ValueGenerator) {
            var credentialCopy = null,
                deferred = $q.defer();
            $scope.$log = $log;
            $scope.saveError = '';
            $scope.getError = '';
            $scope.credentialPairConflicts = null;
            $scope.hasMetadata = false;
            $scope.hasView = false;
            // TODO: get this from the credential return
            $scope.hasModify = true;

            if ($stateParams.credentialId) {
                CredentialServices.get({'id': $stateParams.credentialId}).$promise.then(function(credentialServices) {
                    $scope.credentialServices = credentialServices.services;
                });

                Credential.get({'id': $stateParams.credentialId}).$promise.then(function(credential) {
                    var _credentialPairs = [],
                        _metadata = [];
                    if (Object.entries(credential.credential_pairs).length) {
                        angular.forEach(credential.credential_pairs, function(value, key) {
                            this.push({'key': key, 'value': value});
                        }, _credentialPairs);
                        credential.credentialPairs = _credentialPairs;
                        $scope.hasView = true;
                    }
                    if (credential.credential_keys.length) {
                        $scope.hasMetadata = true;
                    }
                    angular.forEach(credential.metadata, function(value, key) {
                        this.push({'key': key, 'value': value});
                    }, _metadata);
                    credential.credentialPairs = _credentialPairs;
                    credential.mungedMetadata = _metadata;
                    $scope.credential = credential;
                    credentialCopy = angular.copy($scope.credential);
                    $scope.shown = false;
                }, function(res) {
                    if (res.status === 500) {
                        $scope.getError = 'Unexpected server error.';
                        $log.error(res);
                    } else {
                        $scope.getError = res.data.error;
                    }
                    deferred.reject();
                });
            } else {
                // A new credential is being created
                $scope.credential = {
                    name: '',
                    enabled: true,
                    credentialPairs: [{'key': '', 'value': ''}],
                    mungedMetadata: []
                };
                credentialCopy = angular.copy($scope.credential);
                $scope.shown = true;
                $scope.hasView = true;
                $scope.hasModify = true;
                // TODO: need a hasCreate here, which we'd get determine
                // based on config endpoint.
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

            $scope.filterMetadata = function(metadataItem) {
                return metadataItem.isDeleted !== true;
            };

            $scope.getCredentialByID = function(id) {
                return $filter('filter')($scope.$parent.credentialList, {'id': id})[0];
            };

            $scope.getBlindCredentialByID = function(id) {
                return $filter('filter')($scope.$parent.blindCredentialList, {'id': id})[0];
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

            $scope.deleteMetadata = function($$hashKey) {
                var filtered = $filter('filter')($scope.credential.mungedMetadata, {'$$hashKey': $$hashKey});
                if (filtered.length) {
                    filtered[0].isDeleted = true;
                }
            };

            $scope.addMetadata = function() {
                $scope.credential.mungedMetadata.push({
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
                _credential.documentation = $scope.credential.documentation;
                _credential.credential_pairs = {};
                _credential.metadata = {};
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
                // Ensure metadata keys are unique and transform them
                // into key/value dict.
                for (i = $scope.credential.mungedMetadata.length; i--;) {
                    var metadataItem = $scope.credential.mungedMetadata[i];
                    if (metadataItem.isDeleted) {
                        $scope.credential.mungedMetadata.splice(i, 1);
                        continue;
                    }
                    if (metadataItem.key in _credential.metadata) {
                        $scope.saveError = 'Metadata keys must be unique.';
                        return $scope.saveError;
                    }
                    _credential.metadata[metadataItem.key] = metadataItem.value;
                }
                if (angular.equals(credentialCopy, $scope.credential)) {
                    $scope.saveError = 'No changes made.';
                    deferred.reject();
                    return deferred.promise;
                }
                // Update an existing credential.
                if ($scope.credential.id) {
                    Credential.update({'id': $scope.credential.id}, _credential).$promise.then(function(newCredential) {
                        var _credentialPairs = [],
                            _metadata = [];
                        angular.forEach(newCredential.credential_pairs, function(value, key) {
                            this.push({'key': key, 'value': value});
                        }, _credentialPairs);
                        angular.forEach(newCredential.metadata, function(value, key) {
                            this.push({'key': key, 'value': value});
                        }, _metadata);
                        newCredential.credentialPairs = _credentialPairs;
                        newCredential.mungedMetadata = _metadata;
                        $scope.credential = newCredential;
                        if (credentialCopy.name !== $scope.credential.name ||
                            credentialCopy.enabled !== $scope.credential.enabled) {
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
                        $location.path('/resources/credentials/' + newCredential.id);
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

            $scope.generateValue = function(credentialPair) {
              ValueGenerator.get().$promise.then(function(obj) {
                credentialPair.value = obj.value;
              });
            };


        }])

    ;
})(window.angular);
