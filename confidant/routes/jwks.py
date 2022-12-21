import logging

from flask import blueprints, jsonify, request

from confidant import authnz
from confidant.services.jwkmanager import jwk_manager
from confidant.schema.jwks import jwt_response_schema, JWTResponse, \
    jwks_list_response_schema, JWKSListResponse


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
    environment = request.args.get('environment', type=str)

    if not environment:
        return jsonify({'error': 'Please specify an environment'}), 400

    payload = {
        'user': user,
        'is_service': authnz.user_is_service(user),
    }
    try:
        token = jwk_manager.get_jwt(environment, payload)
    except ValueError:
        response = jsonify({'error': 'Key not available for this environment'})
        return response, 400

    return jwt_response_schema.dumps(JWTResponse(token=token))


@blueprint.route('/v1/jwks/public/<environment>', methods=['GET'])
def get_public_jwks(environment):
    """
    Returns a the public JWKS for the requested environment

    **Example request**:

    .. sourcecode:: http

       GET /v1/jwks/public/staging

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "kty": "RSA",
         "kid": "staging",
         "n": "123...",
         "e": "AQAB",
         "alg" "RS256",
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 404: Public key not found for this environment
    """
    jwks = jwk_manager.get_jwks(environment)
    if jwks:
        return jwks_list_response_schema.dumps(JWKSListResponse(keys=jwks))

    response = jsonify({
        'error': 'Public key not found for this environment'
    })
    return response, 404
