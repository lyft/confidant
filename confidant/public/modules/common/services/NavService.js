(function(angular) {
    'use strict';

    angular.module('confidant.common.services.NavService', [])

    .service('common.NavService', [
        '$rootScope',
        function($rootScope) {
            var _this = this;
            this.viewLocation = '';
            this.historyView = '';
            $rootScope.$on('$stateChangeSuccess', function(evt, state) {
                if(state.data) {
                    _this.viewLocation = state.data.viewLocation;
                    _this.historyView = state.data.historyView;
                }
            });

            this.getViewLocation = function() {
                return _this.viewLocation;
            };

            this.getHistoryView = function() {
                return _this.historyView;
            };

        }])

    ;

})(window.angular);
