(function(angular) {
    'use strict';

    angular.module('confidant.common.controllers.NavCtrl', [
        'confidant.common.services.NavService'
    ])

    .controller('common.NavCtrl', [
        '$scope', 'common.NavService',
        function($scope, NavService) {
            $scope.getViewLocation = NavService.getViewLocation;
            $scope.$watch('getViewLocation()', function(newViewLocation, oldViewLocation) {
                if(newViewLocation !== oldViewLocation) {
                    $scope.viewLocation = newViewLocation;
                }
            });
            $scope.getHistoryView = NavService.getHistoryView;
            $scope.$watch('getHistoryView()', function(newHistoryView, oldHistoryView) {
                if(newHistoryView !== oldHistoryView) {
                    $scope.historyView = newHistoryView;
                }
            });
        }])

    ;

})(window.angular);
