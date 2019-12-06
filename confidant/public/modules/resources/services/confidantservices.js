(function(angular) {
    'use strict';

    angular.module('confidant.resources.services.confidantservices', [
        'ngResource',
        'confidant.common.constants'
    ])

    .factory('services.list', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.SERVICES);
    }])

    .factory('services.archiveList', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.ARCHIVE_SERVICES);
    }])

    .factory('services.service', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.SERVICE_METADATA, {id: '@id', revision: '@revision'}, {
            update: {method: 'PUT', isArray: false, url: CONFIDANT_URLS.SERVICE},
            revert: {method: 'PUT', isArray: false, url: CONFIDANT_URLS.SERVICE_REVISION}
        });
    }])

    .factory('services.grants', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.GRANTS, {id: '@id'}, {
            update: {method: 'PUT', isArray: false}
        });
    }])

    .factory('services.archiveServiceRevisions', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.ARCHIVE_SERVICE_REVISIONS, {id: '@id'});
    }])

    .factory('services.services', ['$resource', 'CONFIDANT_URLS', function($resource, CONFIDANT_URLS) {
        return $resource(CONFIDANT_URLS.SERVICES, {}, {
            create: {method: 'POST', isArray: false}
        });
    }])

    .service('services.ServiceListService', [
        '$rootScope',
        'services.list',
        function($rootScope, ServiceList) {
            var _this = this;
            this.serviceList = [];
            $rootScope.$on('updateServiceList', function() {
                ServiceList.get().$promise.then(function(serviceList) {
                    _this.serviceList = serviceList.services;
                });
            });

            this.getServiceList = function() {
                return _this.serviceList;
            };

    }])

    ;

})(window.angular);
