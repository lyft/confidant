(function(angular, _) {
    'use strict';

    angular.module('confidant.common.services.SpinOn', [])


    /**
     * Show and hide a small spinner inside of an element.
     *
     * To use, inject the common.SpinOn factory function, and invoke it like so:
     *
     *     var spin = common.SpinOn($element, optStartCallback, optEndCallback);
     *     spin.start();
     *     // spinner is spinning!
     *     spin.stop();
     *     // spinner is gone
     *
     * Factory function arguments:
     *
     * $element: an angular.element (jQuery object) of the element that should
     *     contain the spinner. Note that this element must support appending
     *     DOM nodes, so `input` will not work correctly. To use an `input`,
     *     wrap it in an element that can contain child nodes (like `div`).
     * optStartCallback: A function to be called before the spinner has
     *     started. It will get passed $element as its only argument.
     * optEndCallback: A function to be called after the spinner has stopped.
     *     It will get passed $element as its only argument.
     */
    .service('common.SpinOn', ['$window', function SpinOn($window) {

        /**
         * Factory function for creating a new spinner.
         *
         * For all params, see the service overview for more details.
         *
         * @param  {angular.Element} $element
         * @param  {function(angular.Element)=} optStartCallback
         * @param  {function(angular.Element)=} optEndCallback
         * @param {Object=} options Additional configuration options for the spinner
         * @return {Object} An object that controls the spinner. It has the
         *                  following API:
         *                  start {function()} Start the spinner.
         *                  stop {function()} Stop the spinner.
         *                  spinner {Spinner} The actual spinner instance.
         */
        return function($element, optStartCallback, optEndCallback, options) {
            var opts = _.assign({
                lines: 13, // The number of lines to draw
                length: 4, // The length of each line
                width: 2, // The line thickness
                radius: 4, // The radius of the inner circle
                corners: 1, // Corner roundness (0..1)
                rotate: 0, // The rotation offset
                direction: 1, // 1: clockwise, -1: counterclockwise
                color: '#fff', // #rgb or #rrggbb or array of colors
                speed: 1, // Rounds per second
                trail: 60, // Afterglow percentage
                shadow: false, // Whether to render a shadow
                hwaccel: true, // Whether to use hardware acceleration
                className: 'spinner', // The CSS class to assign to the spinner
                zIndex: 2e9, // The z-index (defaults to 2000000000)
                top: '50%', // Top position relative to parent
                left: 'calc(100% - 25px)' // Left position relative to parent
            }, options || {}),
            spinner = new $window.Spinner(opts);

            return {
                /**
                 * Start the spinner.
                 *
                 * The start callback will be invoked first, if specified.
                 *
                 * @return {Object} This SpinOn object.
                 */
                start: function() {
                    if (optStartCallback) {
                        optStartCallback($element);
                    }
                    spinner.spin($element[0]);
                    return this;
                },
                /**
                 * Stop the spinner.
                 *
                 * The stop callback will be invoked after, if specified.
                 *
                 * @return {Object} This SpinOn object.
                 */
                stop: function() {
                    spinner.stop();
                    if (optEndCallback) {
                        optEndCallback($element);
                    }
                    return this;
                },
                /**
                 * The actual Spinner instance.
                 * @type {Spinner}
                 */
                spinner: spinner
            };
        };
    }])
    ;
}(window.angular, window._));
