(function(angular) {
    'use strict';

    angular.module('confidant.common.directives.loadingSpinner', [
        'confidant.common.constants',
        'confidant.common.services.$body',
        'confidant.common.services.SpinOn'
    ])

    /**
     * A directive that shows a loading spinner over the whole page.
     *
     * This directive registers a global loading spinner that responds to events
     * on the current scope. Only one of these should be used per-page, since it
     * appears above all other content in the center of the window.
     *
     * This directive accepts a single parameter, which is an optional classname
     * to be added to <body> while the spinner is active.
     *
     * Usage:
     *
     *     <div loading-spinner="classname-for-body"></div>
     *
     * The spinner will appear when {common.APP_EVENTS.START_REQUEST} or
     * {common.APP_EVENTS.SHOW_SPINNER} are broadcast. It will hide when
     * {common.APP_EVENTS.END_REQUEST} or {common.APP_EVENTS.HIDE_SPINNER}
     * are broadcast.
     *
     * {START_REQUEST} and {END_REQUEST} are broadcast by {http.HttpEventInterceptor},
     * so the spinner will appear during all HTTP requests.
     */
    .directive('loadingSpinner', [
        '$body', 'common.APP_EVENTS', 'common.SpinOn',
        function($body, APP_EVENTS, SpinOn) {
            return {
                restrict: 'A',
                link: function ($scope, $element, attrs) {
                    var activelyShowing = false,
                        loadingClass = attrs.loadingSpinner,

                        spinner = new SpinOn($element,
                            function() {
                                if (loadingClass) {
                                    $body.addClass(loadingClass);
                                }
                                $element.show();
                                activelyShowing = true;
                            },
                            function() {
                                if (loadingClass) {
                                    $body.removeClass(loadingClass);
                                }
                                $element.hide();
                                activelyShowing = false;
                            },
                            {
                                // Make this bigger than the default spinner
                                length: 5,
                                width: 3,
                                radius: 11,
                                // Don't sit on top of interstitials
                                zIndex: 8000,
                                // Position in the middle of the window
                                position: 'fixed',
                                top: '50%',
                                left: '50%'
                            }
                        ),

                        // TODO (hliebowitz): debounce this so that it only shows
                        // if the work performed is > 50ms.
                        show = function() {
                           if (!activelyShowing) {
                               spinner.start();
                           }
                        },
                        hide = function() {
                            if (activelyShowing) {
                                spinner.stop();
                            }
                        };

                    $scope.$on(APP_EVENTS.START_REQUEST, show);
                    $scope.$on(APP_EVENTS.SHOW_SPINNER, show);

                    $scope.$on(APP_EVENTS.END_REQUEST, hide);
                    $scope.$on(APP_EVENTS.HIDE_SPINNER, hide);
                }
            };
        }
    ])
    ;
}(window.angular));
