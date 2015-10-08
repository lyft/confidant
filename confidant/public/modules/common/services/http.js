(function(angular, _) {
    'use strict';

    angular.module('confidant.common.services.http', [
        'confidant.common.constants'
    ])

    /**
     * A response interceptor that broadcasts start and end events.
     *
     * common.APP_EVENTS.START_REQUEST will be broadcast on the root scope every
     * time a new request is started. common.APP_EVENTS.END_REQUEST will be broadcast
     * on the root scope after the last request has completed.
     *
     * To suppress events for a particular request, set {notify: false} on the
     * request's config object.
     */
    .factory('common.HttpEventInterceptor', [
        '$q', '$rootScope', 'common.APP_EVENTS',
        function($q, $rootScope, APP_EVENTS) {

            var pendingRequests = 0,
                notifyFinish = false;

            /**
             * Whether to broadcast events for this request.
             *
             * If a request's config object specifies {notify: false}, then no
             * events will be broadcast for the request.
             *
             * @param  {Object} config A $http config object.
             * @return {Boolean} Whether to broadcast events for this request.
             */
            function shouldNotify(config) {
                return _.isUndefined(config.notify) || !!config.notify;
            }

            /**
             * Send a notification when a request has started.
             *
             * @param {Object} config An $http config object.
             */
            function start(config) {
                pendingRequests += 1;
                if (shouldNotify(config)) {
                    notifyFinish = true;
                    $rootScope.$broadcast(APP_EVENTS.START_REQUEST);
                }
            }

            /**
             * Send a notification when all outstanding requests have completed.
             */
            function finish() {
                if (pendingRequests > 0) {
                    pendingRequests -= 1;
                    if (pendingRequests < 1 && notifyFinish) {
                        $rootScope.$broadcast(APP_EVENTS.END_REQUEST);
                        notifyFinish = false;
                    }
                }
            }

            return {
                request: function(config) {
                    start(config);
                    return config;
                },

                requestError: function(rejection) {
                    finish();
                    return $q.reject(rejection);
                },

                response: function(response) {
                    finish();
                    return response;
                },

                responseError: function(rejection) {
                    finish();
                    return $q.reject(rejection);
                }
            };
        }
    ])

    ;

}(window.angular, window._));
