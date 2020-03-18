###
API
###

Confidant has an API that can be used for programmatic access from the UI, libraries, or CLIs. Authentication is required for all endpoints, and the allowed types of authentication (kmsauth, SAML, OAuth, etc.) are based on your configuration and RBAC settings. See configuration and RBAC documentation for more information about authentication and authorization.

***********************
API route documentation
***********************

.. qrefflask:: confidant.wsgi:app
   :endpoints:
   :undoc-static:

.. autoflask:: confidant.wsgi:app
   :endpoints:
   :undoc-static:
