import os
import logging

from flask import blueprints, current_app, send_from_directory
from werkzeug.exceptions import NotFound

from confidant import authnz, settings

logger = logging.getLogger(__name__)
blueprint = blueprints.Blueprint('static_files', __name__)


@blueprint.route('/')
@authnz.redirect_to_logout_if_no_auth
def index():
    return current_app.send_static_file('index.html')


@blueprint.route('/loggedout')
@authnz.require_logout_for_goodbye
def goodbye():
    return current_app.send_static_file('goodbye.html')


@blueprint.route('/healthcheck')
def healthcheck():
    return '', 200


@blueprint.route('/favicon.ico')
def favicon():
    return current_app.send_static_file('favicon.ico')


@blueprint.route('/404.html')
def not_found():
    return current_app.send_static_file('404.html')


@blueprint.route('/robots.txt')
def robots():
    return current_app.send_static_file('robots.txt')


@blueprint.route('/components/<path:path>')
@blueprint.route('/bower_components/<path:path>')
def components(path):
    return current_app.send_static_file(os.path.join('components', path))


@blueprint.route('/modules/<path:path>')
def modules(path):
    return current_app.send_static_file(os.path.join('modules', path))


@blueprint.route('/styles/<path:path>')
def static_proxy(path):
    return current_app.send_static_file(os.path.join('styles', path))


@blueprint.route('/scripts/<path:path>')
def scripts(path):
    return current_app.send_static_file(os.path.join('scripts', path))


@blueprint.route('/fonts/<path:path>')
def fonts(path):
    return current_app.send_static_file(os.path.join('fonts', path))


@blueprint.route('/images/<path:path>')
def images(path):
    return current_app.send_static_file(os.path.join('images', path))


@blueprint.route('/custom/modules/<path:path>')
@authnz.require_auth
def custom_modules(path):
    if not settings.CUSTOM_FRONTEND_DIRECTORY:
        return '', 200
    try:
        return send_from_directory(
            os.path.join(settings.CUSTOM_FRONTEND_DIRECTORY, 'modules'),
            path
        )
    except NotFound:
        logger.warning(
            'Client requested missing custom module {0}.'.format(path)
        )
        return '', 200


@blueprint.route('/custom/styles/<path:path>')
@authnz.require_auth
def custom_styles(path):
    if not settings.CUSTOM_FRONTEND_DIRECTORY:
        return '', 404
    return send_from_directory(
        os.path.join(settings.CUSTOM_FRONTEND_DIRECTORY, 'styles'),
        path
    )


@blueprint.route('/custom/images/<path:path>')
@authnz.require_auth
def custom_images(path):
    if not settings.CUSTOM_FRONTEND_DIRECTORY:
        return '', 404
    return send_from_directory(
        os.path.join(settings.CUSTOM_FRONTEND_DIRECTORY, 'images'),
        path
    )
