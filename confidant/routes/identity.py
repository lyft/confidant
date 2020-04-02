from flask import blueprints, jsonify

from confidant import authnz, settings
from confidant.utils import misc

blueprint = blueprints.Blueprint('identity', __name__)

acl_module_check = misc.load_module(settings.ACL_MODULE)


@blueprint.route('/v1/login', methods=['GET', 'POST'])
def login():
    '''
    Send user through login flow. Response depends on configured authentication
    plugin.

    .. :quickref: Authenticate; Send user through login flow.

    **Example request**:

    .. sourcecode:: http

       GET /v1/login
    '''
    return authnz.log_in()


@blueprint.route('/v1/user/email', methods=['GET', 'POST'])
@authnz.require_auth
def get_user_info():
    '''
    Get the email associated with the currently authenticated user.

    .. :quickref: Email Address; Get the email address associated with the
                  currently authenticated user.

    **Example request**:

    .. sourcecode:: http

       GET /v1/user/email

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "email": "rlane@example.com"
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    '''
    try:
        response = jsonify({'email': authnz.get_logged_in_user()})
    except authnz.UserUnknownError:
        response = jsonify({'email': None})
    return response


@blueprint.route('/v1/client_config', methods=['GET'])
@authnz.require_auth
def get_client_config():
    '''
    Get configuration to help clients bootstrap themselves.

    .. :quickref: Client Configuration; Get configuration to help clients
                  bootstrap themselves.

    **Example request**:

    .. sourcecode:: http

       GET /v1/client_config

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "defined": {},
         "generated": {
           "kms_auth_manage_grants": false,
           "aws_accounts": [],
           "xsrf_cookie_name": "XSRF_COOKIE",
           "maintenance_mode": false,
           "history_page_limit": 500,
           "permissions": {
             "list": true,
             "create": true
           }
         }
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    '''
    permissions = {
        'credentials': {
            'list': acl_module_check(resource_type='credential', action='list'),
            'create': acl_module_check(
                resource_type='credential',
                action='create',
            ),
        },
        'blind_credentials': {
            'list': True,
            'create': True,
        },
        'services': {
            'list': acl_module_check(resource_type='service', action='list'),
            'create': acl_module_check(
                resource_type='service',
                action='create',
            ),
        },
    }
    tags = set()
    tags.update(settings.TAGS_EXCLUDING_ROTATION)
    tags.update(settings.ROTATION_DAYS_CONFIG.keys())
    response = jsonify({
        'defined': settings.CLIENT_CONFIG,
        'generated': {
            'kms_auth_manage_grants': settings.KMS_AUTH_MANAGE_GRANTS,
            'aws_accounts': list(settings.SCOPED_AUTH_KEYS.values()),
            'xsrf_cookie_name': settings.XSRF_COOKIE_NAME,
            'maintenance_mode': settings.MAINTENANCE_MODE,
            'history_page_limit': settings.HISTORY_PAGE_LIMIT,
            'defined_tags': list(tags),
            'permissions': permissions,
        }
    })
    return response
