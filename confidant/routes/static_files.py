import os
import logging

from flask import send_from_directory
from werkzeug.exceptions import NotFound

from confidant import authnz
from confidant.app import app


@app.route('/')
@authnz.redirect_to_logout_if_no_auth
def index():
    return app.send_static_file('index.html')


@app.route('/loggedout')
@authnz.require_logout_for_goodbye
def goodbye():
    return app.send_static_file('goodbye.html')


@app.route('/healthcheck')
def healthcheck():
    return '', 200


@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')


@app.route('/404.html')
def not_found():
    return app.send_static_file('404.html')


@app.route('/robots.txt')
def robots():
    return app.send_static_file('robots.txt')


@app.route('/bower_components/<path:path>')
def components(path):
    return app.send_static_file(os.path.join('bower_components', path))


@app.route('/modules/<path:path>')
def modules(path):
    return app.send_static_file(os.path.join('modules', path))


@app.route('/styles/<path:path>')
def static_proxy(path):
    return app.send_static_file(os.path.join('styles', path))


@app.route('/scripts/<path:path>')
def scripts(path):
    return app.send_static_file(os.path.join('scripts', path))


@app.route('/fonts/<path:path>')
def fonts(path):
    return app.send_static_file(os.path.join('fonts', path))


@app.route('/custom/modules/<path:path>')
@authnz.require_auth
def custom_modules(path):
    if not app.config['CUSTOM_FRONTEND_DIRECTORY']:
        return '', 200
    try:
        return send_from_directory(
            os.path.join(app.config['CUSTOM_FRONTEND_DIRECTORY'], 'modules'),
            path
        )
    except NotFound:
        logging.warning(
            'Client requested missing custom module {0}.'.format(path)
        )
        return '', 200


@app.route('/custom/styles/<path:path>')
@authnz.require_auth
def custom_styles(path):
    if not app.config['CUSTOM_FRONTEND_DIRECTORY']:
        return '', 404
    return send_from_directory(
        os.path.join(app.config['CUSTOM_FRONTEND_DIRECTORY'], 'styles'),
        path
    )


@app.route('/custom/images/<path:path>')
@authnz.require_auth
def custom_images(path):
    if not app.config['CUSTOM_FRONTEND_DIRECTORY']:
        return '', 404
    return send_from_directory(
        os.path.join(app.config['CUSTOM_FRONTEND_DIRECTORY'], 'images'),
        path
    )
