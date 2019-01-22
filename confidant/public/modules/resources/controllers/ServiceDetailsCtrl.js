(function(angular) {
    'use strict';

    angular.module('confidant.resources.controllers.ServiceDetailsCtrl', [
        'ui.router',
        'ngResource',
        'xeditable',
        'confidant.resources.services'
    ])


    .controller('resources.ServiceDetailsCtrl', [
        '$scope',
        '$stateParams',
        '$q',
        '$log',
        '$filter',
        '$location',
        'services.service',
        'services.services',
        'roles.list',
        'services.grants',
        function ($scope, $stateParams, $q, $log, $filter, $location, Service, Services, Roles, Grants) {
            var serviceCopy = null;
            $scope.showGrants = $scope.clientconfig.generated.kms_auth_manage_grants;
            $scope.$log = $log;
            $scope.saveError = '';
            $scope.newService = false;
            $scope.credentialPairConflicts = null;
            $scope.aws_account_options = $scope.clientconfig.generated.aws_accounts;

            Roles.get().$promise.then(function(roles) {
                $scope.roles = roles.roles;
            }, function() {
                $scope.roles = [];
            });
            if ($stateParams.serviceId) {
                Service.get({'id': $stateParams.serviceId}).$promise.then(function(service) {
                    $scope.service = service;
                    if ($scope.aws_account_options[0] !== '' && $scope.service.account !== null) {
                        $scope.aws_account_options.unshift('');
                    } else if ($scope.aws_account_options[0] === '' && $scope.service.account === null) {
                        $scope.aws_account_options.shift('');
                    }
                    if (!$scope.service.credentials) {
                        $scope.service.credentials = [];
                    }
                    if (!$scope.service.blind_credentials) {
                        $scope.service.blind_credentials = [];
                    }
                    serviceCopy = angular.copy($scope.service);
                });
                if ($scope.showGrants) {
                    Grants.get({'id': $stateParams.serviceId}).$promise.then(function(grants) {
                        $scope.grants = grants.grants;
                    });
                } else {
                    $scope.grants = null;
                }
            } else {
                $scope.shown = true;
                $scope.service = {
                    id: '',
                    credentials: [],
                    blind_credentials: [],
                    enabled: true,
                    account: null
                };
                serviceCopy = angular.copy($scope.service);
                $scope.newService = true;
                $scope.grants = null;
            }

            $scope.getCredentialByID = function(id) {
                return $filter('filter')($scope.$parent.credentialList, {'id': id})[0];
            };

            $scope.getBlindCredentialByID = function(id) {
                return $filter('filter')($scope.$parent.blindCredentialList, {'id': id})[0];
            };

            $scope.filterCredentials = function(credential) {
                return credential.isDeleted !== true;
            };

            $scope.localeSensitiveComparator = function(v1, v2) {
              // If we don't get strings, just compare by index
              if (v1.type !== 'string' || v2.type !== 'string') {
                return (v1.index < v2.index) ? -1 : 1;
              }

              // Compare strings alphabetically, taking locale into account
              return v1.value.localeCompare(v2.value);
            };

            $scope.filterCredentialOptions = function(credential) {
                var found = false;
                angular.forEach($scope.service.credentials, function(item) {
                    if (credential.id === item.id) {
                        found = true;
                    }
                });
                return credential.enabled === true || found;
            };

            $scope.filterBlindCredentialOptions = function(blind_credential) {
                var found = false;
                angular.forEach($scope.service.blind_credentials, function(item) {
                    if (blind_credential.id === item.id) {
                        found = true;
                    }
                });
                return blind_credential.enabled === true || found;
            };

            $scope.deleteCredential = function($$hashKey) {
                var filtered = $filter('filter')($scope.service.credentials, {'$$hashKey': $$hashKey});
                if (filtered.length) {
                    filtered[0].isDeleted = true;
                }
            };

            $scope.deleteBlindCredential = function($$hashKey) {
                var filtered = $filter('filter')($scope.service.blind_credentials, {'$$hashKey': $$hashKey});
                if (filtered.length) {
                    filtered[0].isDeleted = true;
                }
            };

            $scope.addCredential = function() {
                $scope.service.credentials.push({
                    id: '',
                    name: '',
                    isNew: true
                });
            };

            $scope.addBlindCredential = function() {
                $scope.service.blind_credentials.push({
                    id: '',
                    name: '',
                    isNew: true
                });
            };

            $scope.cancel = function() {
                for (var i = $scope.service.credentials.length; i--;) {
                    var credential = $scope.service.credentials[i];
                    if (credential.isDeleted) {
                        delete credential.isDeleted;
                    }
                    if (credential.isNew) {
                        $scope.service.credentials.splice(i, 1);
                    }
                }
                for (var i = $scope.service.blind_credentials.length; i--;) {
                    var blind_credential = $scope.service.blind_credentials[i];
                    if (blind_credential.isDeleted) {
                        delete blind_credential.isDeleted;
                    }
                    if (blind_credential.isNew) {
                        $scope.service.blind_credentials.splice(i, 1);
                    }
                }
                $scope.credentialPairConflicts = null;
                $scope.saveError = '';
                $scope.service = angular.copy(serviceCopy);
            };

            $scope.ensureGrants = function() {
                var deferred = $q.defer();
                $scope.grantUpdateError = '';
                Grants.update({'id': $scope.service.id}).$promise.then(function(newGrants) {
                    $scope.grants = newGrants.grants;
                    deferred.resolve();
                }, function(res) {
                    if (res.status === 500) {
                        $scope.saveError = 'Unexpected server error.';
                        $log.error(res);
                    } else {
                        $scope.grantUpdateError = res.data.error;
                    }
                    deferred.reject();
                });
                return deferred.promise;
            };

            $scope.checkNewServiceSave = function(serviceId) {
                var deferred = $q.defer();
                if ($scope.newService) {
                    Service.get({'id': serviceId}).$promise.then(function() {
                        $scope.saveError = 'Service with id ' + serviceId +
                                           ' already exists. Cannot create new service.';
                    }, function(res) {
                        if (res.status !== 404) {
                            $scope.saveError = 'Failed to check if service already exists.';
                        }
                    }).finally(function() {
                        if ($scope.saveError !== '') {
                            deferred.reject();
                        } else {
                            deferred.resolve();
                        }
                    });
                } else {
                    deferred.resolve();
                }
                return deferred.promise;
            }

            $scope.saveService = function() {
                var _service = {},
                    deferred = $q.defer();
                _service.id = $scope.service.id;
                _service.account = $scope.service.account;
                _service.enabled = $scope.service.enabled;
                _service.credentials = [];
                _service.blind_credentials = [];
                $scope.credentialPairConflicts = null;
                $scope.saveError = '';
                // Ensure credentials are unique and flatten credentiaList into a list of ids.
                for (var i = $scope.service.credentials.length; i--;) {
                    var credential = $scope.service.credentials[i];
                    if (credential.isDeleted) {
                        $scope.service.credentials.splice(i, 1);
                        continue;
                    }
                    if (_service.credentials.indexOf(credential.id) > -1) {
                        $scope.saveError = 'Credentials must be unique.';
                        return $scope.saveError;
                    }
                    _service.credentials.push(credential.id);
                }
                for (var i = $scope.service.blind_credentials.length; i--;) {
                    var blind_credential = $scope.service.blind_credentials[i];
                    if (blind_credential.isDeleted) {
                        $scope.service.blind_credentials.splice(i, 1);
                        continue;
                    }
                    if (_service.blind_credentials.indexOf(blind_credential.id) > -1) {
                        $scope.saveError = 'Credentials must be unique.';
                        return $scope.saveError;
                    }
                    _service.blind_credentials.push(blind_credential.id);
                }
                if (angular.equals(serviceCopy, $scope.service)) {
                    $scope.saveError = 'No changes made.';
                    deferred.reject();
                    return deferred.promise;
                }
                Service.update({'id': $scope.service.id}, _service).$promise.then(function(newService) {
                    $scope.$emit('updateServiceList');
                    $scope.service = newService;
                    serviceCopy = angular.copy($scope.service);
                    deferred.resolve();
                    if ($scope.newService) {
                        $location.path('/resources/service/' + newService.id);
                    }
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
