import logging

import flask
from flask import blueprints, jsonify, request, session

from confidant import authnz, settings

logger = logging.getLogger(__name__)
blueprint = blueprints.Blueprint('saml', __name__)


@blueprint.route('/v1/saml/metadata', methods=['GET'])
def get_saml_metadata():
    """
    Generate SAML metadata XML describing the service endpoints.
    """
    return authnz.user_mod.generate_metadata()


@blueprint.route('/v1/saml/consume', methods=['POST'])
def consume_saml_assertion():
    """
    The SAML attribute consumer service receives POST callbacks from the IdP.
    """
    return authnz.user_mod.consume_saml_assertion()


@blueprint.route('/v1/saml/login', methods=['GET'])
def generate_saml_login_redirect():
    """
    Redirect to the SAML login page. You don't normally need to hit this
    since any page with @authnz.require_auth will redirect to login.
    """
    return flask.redirect(
        authnz.user_mod.login_redirect_url(return_to='/v1/saml/debug'))


@blueprint.route('/v1/saml/logout', methods=['GET'])
def saml_logout():
    """
    This dual purpose route both initiates SingleLogOut redirects to the IdP
    and receives the HTTP-REDIRECT callback (also a GET) from the IdP post
    logout.
    """

    if 'SAMLResponse' in request.args or 'SAMLRequest' in request.args:
        # callback
        return authnz.user_mod.log_out_callback()
    else:
        # initial
        return authnz.user_mod.log_out()


@blueprint.route('/v1/saml/debug', methods=['GET'])
def dump_session_info():
    """Debug endpoint to show SAML attributes."""

    if not settings.SAML_DEBUG:
        msg = "Cannot display /debug, not in DEBUG mode."
        logger.info(msg)
        return flask.make_response(msg, 403)

    return jsonify(session=session.items(), headers=request.headers.items())
