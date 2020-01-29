import logging

from flask import blueprints, jsonify, request

from confidant import authnz, settings
from confidant.services import certificatemanager
from confidant.schema.certificates import (
    certificate_expanded_response_schema,
    CertificateResponse,
)
from confidant.utils import misc

blueprint = blueprints.Blueprint('certificates', __name__)

acl_module_check = misc.load_module(settings.ACL_MODULE)


@blueprint.route('/v1/certificates/<cn>', methods=['GET'])
@authnz.require_auth
def get_certificate(cn):
    '''
    Get a certificate for the provided cn
    '''
    validity = request.args.get(
        'validity',
        default=settings.ACM_PRIVATE_CA_MAX_VALIDITY_DAYS,
        type=int,
    )
    san = request.args.getlist('san')
    if authnz.user_is_user_type('service'):
        # TODO: acl check this, rather than checking service name matches
        if not authnz.user_is_service(cn):
            logging.warning('Authz failed for service {0}.'.format(id))
            msg = 'Service is not authorized to get certificate cn {0}.'
            msg = msg.format(cn)
            return jsonify({'error': msg}), 401
    else:
        logged_in_user = authnz.get_logged_in_user()
        if not acl_module_check(
            resource_type='certificate',
            action='get',
            resource_id=cn,
            kwargs={
                'san': san,
            },
        ):
            msg = "{} does not have access to get certificate cn {}".format(
                authnz.get_logged_in_user(),
                cn
            )
            error_msg = {'error': msg, 'reference': cn}
            return jsonify(error_msg), 403

        logging.info(
            'get_certificate called on id={} by user={}'.format(
                cn,
                logged_in_user,
            )
        )
    certificate = certificatemanager.issue_certificate_with_key(
        cn,
        validity,
        san,
    )
    certificate_response = CertificateResponse(
        certificate=certificate['certificate'],
        certificate_chain=certificate['certificate_chain'],
        key=certificate['key'],
    )
    return certificate_expanded_response_schema.dumps(certificate_response)


@blueprint.route('/v1/certificates', methods=['POST'])
@authnz.require_auth
@authnz.require_csrf_token
def get_certificate_from_csr():
    '''
    Get a certificate for the provided csr
    '''
    data = request.get_json()
    if not data.get('csr'):
        return jsonify(
            {'error': 'csr must be provided in the POST body.'},
        ), 400
    try:
        csr = certificatemanager.decode_csr(data['csr'])
    except Exception:
        logging.exception('Failed to decode PEM csr')
        return jsonify(
            {'error': 'csr could not be decoded'},
        ), 400
    validity = data.get(
        'validity',
        default=settings.ACM_PRIVATE_CA_MAX_VALIDITY_DAYS,
        type=int,
    )
    # Get the cn and san values from the csr object, so that we can use them
    # for the ACL check.
    cn = certificatemanager.get_csr_common_name(csr)
    san = certificatemanager.get_csr_san(csr)
    if authnz.user_is_user_type('service'):
        # TODO: acl check this, rather than checking service name matches
        if not authnz.user_is_service(cn):
            logging.warning('Authz failed for service {0}.'.format(id))
            msg = 'Service is not authorized to get certificate cn {0}.'
            msg = msg.format(cn)
            return jsonify({'error': msg}), 401
    else:
        logged_in_user = authnz.get_logged_in_user()
        if not acl_module_check(
            resource_type='certificate',
            action='get',
            resource_id=cn,
            kwargs={
                'san': san,
            },
        ):
            msg = "{} does not have access to get certificate cn {}".format(
                authnz.get_logged_in_user(),
                cn
            )
            error_msg = {'error': msg, 'reference': cn}
            return jsonify(error_msg), 403

        logging.info(
            'get_certificate called on id={} by user={}'.format(
                cn,
                logged_in_user,
            )
        )
    certificate = certificatemanager.issue_and_get_certificate(
        data['csr'],
        validity,
    )
    certificate_response = CertificateResponse(
        certificate=certificate['certificate'],
        certificate_chain=certificate['certificate_chain'],
    )
    return certificate_expanded_response_schema.dumps(certificate_response)
