import logging

from flask import blueprints, jsonify

from confidant import authnz
from confidant.services.jwkmanager import jwk_manager
from confidant.schema.jwks import jwt_response_schema, JWTResponse


logger = logging.getLogger(__name__)
blueprint = blueprints.Blueprint('jwks', __name__)


@blueprint.route('/v1/jwks/token', methods=['GET'])
@authnz.require_auth
def get_token():
    """
    Returns a JWT for the authenticated service

    **Example request**:

    .. sourcecode:: http

       GET /v1/jwks/token

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "token": "ey..."
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 400: JWTs are not supported for this user
    """
    user = authnz.get_logged_in_user()
    if authnz.user_is_service(user):
        payload = {
            'service': user,
            'namespace': user.replace('-iad', '')
        }

        if 'development' in user or 'unauthenticated' in user:
            token = jwk_manager.get_jwt('localdev', payload)
        elif 'staging' in user:
            token = jwk_manager.get_jwt('staging', payload)
        elif 'production' in user:
            token = jwk_manager.get_jwt('production', payload)
        else:
            error_msg = 'JWTs are not supported for this user ({0})'.format(
                authnz.get_logged_in_user()
            )
            response = jsonify(error_msg)
            return response, 400

        log_line = "{0} get JWT".format(
            authnz.get_logged_in_user(),
        )
        logger.info(log_line)
    else:
        error_msg = 'JWTs are not supported for this user ({0})'.format(
            authnz.get_logged_in_user()
        )
        response = jsonify(error_msg)
        return response, 400

    return jwt_response_schema.dumps(JWTResponse(token=token))
