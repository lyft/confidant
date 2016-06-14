(function(angular) {
    'use strict';


    angular.module('confidant.history.controllers', [
        // Keep this list sorted alphabetically!
        'confidant.history.controllers.BlindCredentialHistoryCtrl',
        'confidant.history.controllers.CredentialHistoryCtrl',
        'confidant.history.controllers.ResourceHistoryCtrl',
        'confidant.history.controllers.ServiceHistoryCtrl'
    ])
    ;
}(angular));
