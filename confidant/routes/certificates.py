import logging

from flask import blueprints, jsonify, request

from confidant import authnz, settings
from confidant.services import certificatemanager
from confidant.schema.certificates import (
    certificate_authority_response_schema,
    certificate_authorities_response_schema,
    certificate_expanded_response_schema,
    certificate_response_schema,
    CertificateAuthorityResponse,
    CertificateAuthoritiesResponse,
    CertificateResponse,
)
from confidant.utils import misc

logger = logging.getLogger(__name__)
blueprint = blueprints.Blueprint('certificates', __name__)

acl_module_check = misc.load_module(settings.ACL_MODULE)


@blueprint.route('/v1/certificates/<ca>/<cn>', methods=['GET'])
@authnz.require_auth
def get_certificate(ca, cn):
    '''
    Get a certificate from the provided CA, for the provided CN.

    .. :quickref: Certificate; Get certificate from the provided CA, for the
                  provided CN.

    **Example request**:

    .. sourcecode:: http

       GET /v1/certificates/example-ca/service.example.com

    :param ca: The friendly name of the certificate authority to issue a
               certificate against.
    :type ca: str
    :param cn: The canonical name attribute to use in the issued certificate.
    :type cn: str
    :query string san: A subject alternative name attribute to use in the
                       issued certificate. This query parameter can be
                       provided multiple times
    :query int validity: The length (in days) that the issued certificate
                         should be valid for. If this value is longer than
                         the server defined maximum validity length, the
                         validity will be set to the maximum validity length.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "certificate": "---...BEGIN...",
         "certificate_chain": "---...BEGIN...",
         "key": "---...BEGIN..."
       }

    :resheader Content-Type: application/json
    :statuscode 200: success
    :statuscode 403: client does not have access to generate the requested
                     certificate.
    '''
    try:
        ca_object = certificatemanager.get_ca(ca)
    except certificatemanager.CertificateAuthorityNotFoundError:
        return jsonify({'error': 'Provided CA not found.'}), 404
    san = request.args.getlist('san')

    logged_in_user = authnz.get_logged_in_user()
    if not acl_module_check(
        resource_type='certificate',
        action='get',
        resource_id=cn,
        kwargs={
            'ca': ca,
            'san': san,
        },
    ):
        msg = ('{} does not have access to get certificate cn {} against'
               ' ca {}').format(
            authnz.get_logged_in_user(),
            cn,
            ca,
        )
        error_msg = {'error': msg, 'reference': cn}
        return jsonify(error_msg), 403

    logger.info(
        'get_certificate called on id={} for ca={} by user={}'.format(
            cn,
            ca,
            logged_in_user,
        )
    )

    validity = request.args.get(
        'validity',
        default=ca_object.settings['max_validity_days'],
        type=int,
    )
    try:
        certificate = ca_object.issue_certificate_with_key(
            cn,
            validity,
            san,
        )
    except certificatemanager.CertificateNotReadyError:
        # Ratelimit response for a locked certificate in the cache
        error_msg = 'Certificate being requested, please wait and try again.'
        response = jsonify(error_msg)
        response.retry_after = 2
        return response, 429
    certificate_response = CertificateResponse(
        certificate=certificate['certificate'],
        certificate_chain=certificate['certificate_chain'],
        key=certificate['key'],
    )
    return certificate_expanded_response_schema.dumps(certificate_response)


@blueprint.route('/v1/certificates/<ca>', methods=['POST'])
@authnz.require_auth
@authnz.require_csrf_token
def get_certificate_from_csr(ca):
    '''
    Get a certificate from the ca provided in the url, using the CSR, validity
    and san provided in the POST body.

    .. :quickref: Certificate; Issue and get a certificate from the provided
                  CA, using a CSR provided in the POST body.

    **Example request**:

    .. sourcecode:: http

       POST /v1/certificates/example-ca

    :<json string ca: The friendly name of the certificate authority to issue
                      a certificate against.
    :<json List[string] san: a list of subject alternative name attributes to
                             use in the issued certificate. This query
                             parameter can be provided multiple times
    :<json int validity: The length (in days) that the issued certificate.
                         should be valid for. If this value is longer than
                         the server defined maximum validity length, the
                         validity will be set to the maximum validity length.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "certificate": "---...BEGIN...",
         "certificate_chain": "---...BEGIN..."
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 400: Invalid input; either the CSR was unsbale to be decoded,
                     or was missing from the request.
    :statuscode 403: Client does not have access to generate the requested
                     certificate.
    '''
    try:
        ca_object = certificatemanager.get_ca(ca)
    except certificatemanager.CertificateAuthorityNotFoundError:
        return jsonify({'error': 'Provided CA not found.'}), 404
    data = request.get_json()
    if not data or not data.get('csr'):
        return jsonify(
            {'error': 'csr must be provided in the POST body.'},
        ), 400
    validity = data.get(
        'validity',
        ca_object.settings['max_validity_days'],
    )
    try:
        csr = ca_object.decode_csr(data['csr'])
    except Exception:
        logger.exception('Failed to decode PEM csr')
        return jsonify(
            {'error': 'csr could not be decoded'},
        ), 400
    # Get the cn and san values from the csr object, so that we can use them
    # for the ACL check.
    cn = ca_object.get_csr_common_name(csr)
    san = ca_object.get_csr_san(csr)

    logged_in_user = authnz.get_logged_in_user()
    if not acl_module_check(
        resource_type='certificate',
        action='get',
        resource_id=cn,
        kwargs={
            'ca': ca,
            'san': san,
        },
    ):
        msg = ('{} does not have access to get certificate cn {} against'
               ' ca {}').format(
            authnz.get_logged_in_user(),
            cn,
            ca,
        )
        error_msg = {'error': msg, 'reference': cn}
        return jsonify(error_msg), 403

    logger.info(
        'get_certificate called on id={} for ca={} by user={}'.format(
            cn,
            ca,
            logged_in_user,
        )
    )

    arn = ca_object.issue_certificate(data['csr'], validity)
    certificate = ca_object.get_certificate_from_arn(arn)
    certificate_response = CertificateResponse(
        certificate=certificate['certificate'],
        certificate_chain=certificate['certificate_chain'],
    )
    return certificate_response_schema.dumps(certificate_response)


@blueprint.route('/v1/cas', methods=['GET'])
@authnz.require_auth
def list_cas():
    '''
    List the configured CAs.

    .. :quickref: Certificate Authorities; Get a list of the detailed
                  certificate authorities configured on the server.

    **Example request**:

    .. sourcecode:: http

       GET /v1/cas

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "cas": [
           "example-ca": {
             "certificate": "---...BEGIN...",
             "certificate_chain": "---...BEGIN...",
             "tags": {
               "hello": "world"
            },
            ...
         ]
       }

    :resheader Content-Type: application/json
    :statuscode 200: success
    :statuscode 403: client does not have access to list CAs
    '''

    logged_in_user = authnz.get_logged_in_user()
    if not acl_module_check(
        resource_type='ca',
        action='list',
    ):
        msg = '{} does not have access to list cas'.format(
            authnz.get_logged_in_user(),
        )
        error_msg = {'error': msg}
        return jsonify(error_msg), 403

    cas = certificatemanager.list_cas()

    logger.info('list_cas called by user={}'.format(logged_in_user))

    cas_response = CertificateAuthoritiesResponse.from_cas(cas)
    return certificate_authorities_response_schema.dumps(cas_response)


@blueprint.route('/v1/cas/<ca>', methods=['GET'])
@authnz.require_auth
def get_ca(ca):
    '''
    Get the CA information for the provided ca.

    .. :quickref: Certificate Authorities; Get the detailed certificate
                  authority information for the specified CA.

    **Example request**:

    .. sourcecode:: http

       GET /v1/cas/example-ca

    :param ca: The friendly name of the certificate authority to issue a
               certificate against.
    :type ca: str

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "example-ca": {
           "certificate": "---...BEGIN...",
           "certificate_chain": "---...BEGIN...",
           "tags": {
             "hello": "world"
          }
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have access to get the requested CA.
    '''
    try:
        ca_object = certificatemanager.get_ca(ca)
    except certificatemanager.CertificateAuthorityNotFoundError:
        return jsonify({'error': 'Provided CA not found.'}), 404

    logged_in_user = authnz.get_logged_in_user()
    if not acl_module_check(
        resource_type='ca',
        action='get',
        resource_id=ca,
    ):
        msg = '{} does not have access to get ca {}'.format(
            authnz.get_logged_in_user(),
            ca,
        )
        error_msg = {'error': msg, 'reference': ca}
        return jsonify(error_msg), 403

    logger.info(
        'get_ca called on id={} by user={}'.format(
            ca,
            logged_in_user,
        )
    )

    _ca = ca_object.get_certificate_authority_certificate()
    ca_response = CertificateAuthorityResponse(
        ca=_ca['ca'],
        certificate=_ca['certificate'],
        certificate_chain=_ca['certificate_chain'],
        tags=_ca['tags'],
    )
    return certificate_authority_response_schema.dumps(ca_response)
