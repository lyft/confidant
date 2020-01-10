from flask import blueprints, jsonify

from confidant import authnz, settings
from confidant.utils import misc

blueprint = blueprints.Blueprint('identity', __name__)

acl_module_check = misc.load_module(settings.ACL_MODULE)


@blueprint.route('/v1/login', methods=['GET', 'POST'])
def login():
    '''
    Send user through login flow.
    '''
    return authnz.log_in()


@blueprint.route('/v1/user/email', methods=['GET', 'POST'])
@authnz.require_auth
def get_user_info():
    '''
    Get the email address of the currently logged-in user.
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
    # TODO: add more config in here.
    response = jsonify({
        'defined': settings.CLIENT_CONFIG,
        'generated': {
            'kms_auth_manage_grants': settings.KMS_AUTH_MANAGE_GRANTS,
            'aws_accounts': list(settings.SCOPED_AUTH_KEYS.values()),
            'xsrf_cookie_name': settings.XSRF_COOKIE_NAME,
            'maintenance_mode': settings.MAINTENANCE_MODE,
            'history_page_limit': settings.HISTORY_PAGE_LIMIT,
            'permissions': permissions,
        }
    })
    return response
