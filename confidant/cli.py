# -*- coding: utf-8 -*-
"""Confidant cli module."""

# Import python libs
import logging
import json
import argparse
import sys
import getpass
import re

import confidant.client
import confidant.services

KEY_BAD_PATTERN = re.compile(r'(\W|^\d)')


def _get_client_from_args(args):
    if args.mfa:
        mfa_pin = getpass.getpass('Enter the MFA code: ')
    else:
        mfa_pin = None
    auth_context = {}
    if args._from:
        auth_context['from'] = args._from
    if args._to:
        auth_context['to'] = args._to
    if args.user_type:
        auth_context['user_type'] = args.user_type
    if not auth_context:
        auth_context = None
    if args.config_files:
        config_files = args.config_files.split(',')
    else:
        config_files = None
    client = confidant.client.ConfidantClient(
        args.url,
        args.auth_key,
        auth_context,
        token_lifetime=args.token_lifetime,
        token_version=args.token_version,
        assume_role=args.assume_role,
        mfa_pin=mfa_pin,
        region=args.region,
        retries=args.retries,
        config_files=config_files,
        profile=args.profile
    )
    return client


def _parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=('A client for fetching credentials from a confidant'
                     ' server.'),
        add_help=False
    )
    parser.add_argument(
        '-h',
        '--help',
        action=_HelpAction,
        help='show this help message and exit'
    )
    parser.add_argument(
        '--config-files',
        help=('Comma separated list of configuration files to use. Default:'
              ' ~/.confidant,/etc/confidant/config')
    )
    parser.add_argument(
        '--profile',
        help='Configuration profile to use. Default: default'
    )
    parser.add_argument(
        '-u',
        '--url',
        help=('url of the confidant server. i.e.'
              ' https://confidant-production.example.com')
    )
    parser.add_argument(
        '--retries',
        help=('Number of retries that should be attempted on confidant server'
              ' errors. Default 0.'),
        type=int
    )
    parser.add_argument(
        '-k',
        '--auth-key',
        help='The KMS auth key to use. i.e. alias/authnz-production'
    )
    parser.add_argument(
        '-l',
        '--token-lifetime',
        type=int,
        help=('The token lifetime, in minutes. The client will backdate the'
              ' token by 3 minutes to avoid clockskew issues, so the minimum'
              ' lifetime you should use is 4. You may also want to pad the'
              ' lifetime by a few minutes to avoid clock skew the other'
              ' direction, so a safe recommended minimum is 7.')
    )
    parser.add_argument(
        '--token-version',
        type=int,
        help='The version of the KMS auth token.'
    )
    parser.add_argument(
        '--from',
        dest='_from',
        help=('The IAM role or user to authenticate with. i.e.'
              ' myservice-production or myuser')
    )
    parser.add_argument(
        '--to',
        dest='_to',
        help='The IAM role name of confidant i.e. confidant-production'
    )
    parser.add_argument(
        '--user-type',
        help='The confidant user-type to authenticate as i.e. user or service'
    )
    parser.add_argument(
        '--mfa',
        help='Prompt for an MFA token.',
        action='store_true',
        dest='mfa'
    )
    parser.add_argument(
        '--assume-role',
        help='Assume the specified role.'
    )
    parser.add_argument(
        '--region',
        help='Use the specified region for authentication.'
    )
    parser.add_argument(
        '--log-level',
        help='Logging verbosity.',
        default='info'
    )
    parser.add_argument(
        '--version',
        help='Print version and exit.',
        action='version',
        version='%(prog)s {version}'.format(version=confidant.VERSION)
    )
    parser.set_defaults(mfa=False)

    subparsers = parser.add_subparsers(dest='subcommand')
    get_service_parser = subparsers.add_parser('get_service')
    get_service_parser.add_argument(
        '--service',
        help='The service to get.'
    )
    get_service_parser.add_argument(
        '--no-decrypt-blind',
        help=('Do not decrypt blind credentials, instead give back the raw'
              ' results from get_service.'),
        action='store_false',
        dest='decrypt_blind'
    )
    get_service_parser.set_defaults(
        decrypt_blind=True
    )

    create_blind_cred_parser = subparsers.add_parser('create_blind_credential')
    create_blind_cred_parser.add_argument(
        '--blind-keys',
        required=True,
        help=('A dict of region to kms key mappings to use for at-rest'
              ' encryption for multiple regions in json format i.e.'
              ' {"us-east-1":"alias/confidant-production-blind-useast1",'
              '"us-west-2":"alias/confidant-production-blind-uswest2"}'),
        type=json.loads
    )
    context_group = create_blind_cred_parser.add_mutually_exclusive_group(
        required=True
    )
    context_group.add_argument(
        '--group-context',
        help=('A encryption context for blind credentials in json format i.e.'
              ' {"group":"web-production"}. This context will be applied to'
              ' all regions, if multiple regions are provided in --blind-keys.'
              ' Mutually exclusive with --blind-contexts.'),
        type=json.loads
    )
    context_group.add_argument(
        '--blind-contexts',
        help=('A custom dict of region to encryption context for blind'
              ' credentials in json format i.e.'
              ' \'{"us-east-1":{"to":"web-production-useast1"},'
              '"us-west-2":{"to":"web-production-uswest2"}}\'. Mutually'
              ' exclusive with --group-context.'),
        type=json.loads
    )
    create_blind_cred_parser.add_argument(
        '--name',
        required=True,
        help='A name for this blind credential i.e. \'production ssl key\'.'
    )
    create_blind_cred_parser.add_argument(
        '--credential-pairs',
        required=True,
        help=('A dict of key/value pairs for credentials in json format i.e.'
              '\'{"ssl_key":"----- BEGIN...","ssl_cert":"----- BEGIN..."}\'.'),
        type=json.loads
    )
    create_blind_cred_parser.add_argument(
        '--cipher-type',
        help='The type of cipher to use for at-rest encryption.',
        default='fernet'
    )
    create_blind_cred_parser.add_argument(
        '--cipher-version',
        help=('The version of the cipher implementation to use for at-rest'
              ' encryption.'),
        default=2
    )
    create_blind_cred_parser.add_argument(
        '--no-store-keys',
        help=('Do not to store the dict keys of credential-pairs as a clear'
              ' text list in the blind-credential metadata. By default the'
              ' dict keys are stored to help ensure blind credentials will not'
              ' conflict with each other when mapped to a service and also to'
              ' aid in use of the credentials in application code (since you'
              ' need to reference the key to get the value).'),
        action='store_false',
        dest='store_keys'
    )
    create_blind_cred_parser.add_argument(
        '--metadata',
        help=('A dict of key/value pairs to be stored as clear-text extensible'
              ' along with the credential in json format i.e. '
              '\'{"path":"/etc/mysecret","mode":"0600"}\'.'),
        type=json.loads,
        default='{}'
    )
    enabled_group = create_blind_cred_parser.add_mutually_exclusive_group()
    enabled_group.add_argument(
        '--enabled',
        help='Enable this credential (default).',
        action='store_true',
        dest='enabled'
    )
    enabled_group.add_argument(
        '--disabled',
        help='Disable this credential.',
        action='store_false',
        dest='enabled'
    )
    create_blind_cred_parser.set_defaults(
        store_keys=True,
        enabled=True
    )

    update_blind_cred_parser = subparsers.add_parser('update_blind_credential')
    update_blind_cred_parser.add_argument(
        '--blind-keys',
        help=('A dict of region to kms key mappings to use for at-rest'
              ' encryption for multiple regions in json format i.e.'
              ' {"us-east-1":"alias/confidant-production-blind-useast1",'
              '"us-west-2":"alias/confidant-production-blind-uswest2"}'),
        type=json.loads
    )
    context_group = update_blind_cred_parser.add_mutually_exclusive_group()
    context_group.add_argument(
        '--group-context',
        help=('A encryption context for blind credentials in json format i.e.'
              ' {"group":"web-production"}. This context will be applied to'
              ' all regions, if multiple regions are provided in --blind-keys.'
              ' Mutually exclusive with --blind-contexts.'),
        type=json.loads
    )
    context_group.add_argument(
        '--blind-contexts',
        help=('A custom dict of region to encryption context for blind'
              ' credentials in json format i.e.'
              ' \'{"us-east-1":{"to":"web-production-useast1"},'
              '"us-west-2":{"to":"web-production-uswest2"}}\'. Mutually'
              ' exclusive with --group-context.'),
        type=json.loads
    )
    update_blind_cred_parser.add_argument(
        '--id',
        required=True,
        help=('An id for this blind credential i.e.'
              ' \'f232fcd3747c47718e48a034f4cdfc0e\'.'),
        dest='_id'
    )
    update_blind_cred_parser.add_argument(
        '--name',
        help='A name for this blind credential i.e. \'production ssl key\'.'
    )
    update_blind_cred_parser.add_argument(
        '--credential-pairs',
        help=('A dict of key/value pairs for credentials in json format i.e.'
              '\'{"ssl_key":"----- BEGIN...","ssl_cert":"----- BEGIN..."}\'.'),
        type=json.loads
    )
    update_blind_cred_parser.add_argument(
        '--cipher-type',
        help='The type of cipher to use for at-rest encryption.'
    )
    update_blind_cred_parser.add_argument(
        '--cipher-version',
        help=('The version of the cipher implementation to use for at-rest'
              ' encryption.')
    )
    update_blind_cred_parser.add_argument(
        '--no-store-keys',
        help=('Do not to store the dict keys of credential-pairs as a clear'
              ' text list in the blind-credential metadata. By default the'
              ' dict keys are stored to help ensure blind credentials will not'
              ' conflict with each other when mapped to a service and also to'
              ' aid in use of the credentials in application code (since you'
              ' need to reference the key to get the value).'),
        action='store_false',
        dest='store_keys'
    )
    update_blind_cred_parser.add_argument(
        '--metadata',
        help=('A dict of key/value pairs to be stored as clear-text extensible'
              ' along with the credential in json format i.e.'
              ' \'{"path":"/etc/mysecret","mode":"0600"}\'.'),
        type=json.loads
    )
    enabled_group = update_blind_cred_parser.add_mutually_exclusive_group()
    enabled_group.add_argument(
        '--enabled',
        help='Enable this credential (default).',
        action='store_true',
        dest='enabled'
    )
    enabled_group.add_argument(
        '--disabled',
        help='Disable this credential.',
        action='store_false',
        dest='enabled'
    )
    update_blind_cred_parser.set_defaults(
        enabled=None,
        store_keys=True
    )

    get_blind_cred_parser = subparsers.add_parser('get_blind_credential')
    get_blind_cred_parser.add_argument(
        '--id',
        required=True,
        help=('An id for this blind credential i.e.'
              ' \'f232fcd3747c47718e48a034f4cdfc0e\'.'),
        dest='_id'
    )
    get_blind_cred_parser.add_argument(
        '--decrypt-blind',
        help=('Decrypt blind credentials, rather than giving back the raw'
              ' results from get_blind_credential.'),
        action='store_true',
        dest='decrypt_blind'
    )
    get_blind_cred_parser.set_defaults(
        decrypt_blind=False
    )

    subparsers.add_parser('list_blind_credentials')

    return parser.parse_args()


def main():
    """Entrypoint function for confidant cli."""
    args = _parse_args()

    numeric_loglevel = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_loglevel, int):
        raise ValueError('Invalid log level: {0}'.format(args.loglevel))
    logging.basicConfig(
        level=numeric_loglevel,
        format='%(asctime)s %(name)s: %(levelname)s %(message)s',
        stream=sys.stderr
    )

    client = _get_client_from_args(args)

    ret = {'result': False}

    if args.subcommand == 'get_service':
        try:
            ret = client.get_service(
                args.service,
                args.decrypt_blind
            )
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'create_blind_credential':
        contexts = {}
        if args.group_context:
            for region in args.blind_keys:
                contexts[region] = args.group_context
        else:
            contexts = args.blind_contexts
        try:
            ret = client.create_blind_credential(
                args.blind_keys,
                contexts,
                args.name,
                args.credential_pairs,
                args.metadata,
                args.cipher_type,
                args.cipher_version,
                args.store_keys,
                args.enabled
            )
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'update_blind_credential':
        contexts = {}
        if args.group_context:
            for region in args.blind_keys:
                contexts[region] = args.group_context
        elif args.blind_contexts:
            contexts = args.blind_contexts
        else:
            contexts = None
        try:
            ret = client.update_blind_credential(
                args._id,
                args.blind_keys,
                contexts,
                args.name,
                args.credential_pairs,
                args.metadata,
                args.cipher_type,
                args.cipher_version,
                args.store_keys,
                args.enabled
            )
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'get_blind_credential':
        try:
            ret = client.get_blind_credential(args._id, args.decrypt_blind)
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'list_blind_credentials':
        try:
            ret = client.list_blind_credentials()
        except Exception:
            logging.exception('An unexpected general error occurred.')

    print json.dumps(ret, sort_keys=True, indent=4, separators=(',', ': '))
    if not ret['result']:
        sys.exit(1)


# http://stackoverflow.com/questions/20094215
class _HelpAction(argparse._HelpAction):

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        print ''

        # retrieve subparsers from parser
        subparsers_actions = [
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)]
        for subparsers_action in subparsers_actions:
            # get all subparsers and print help
            for choice, subparser in subparsers_action.choices.items():
                print ('Subcommand \'{0}\':'.format(choice))
                print (subparser.format_help())

        print (
            'example: confidant_client get_service -u'
            ' "https://confidant-production.example.com" -k'
            ' "alias/authnz-production" --from myservice-production'
            ' --to confidant-production --user_type service'
        )

        parser.exit()


if __name__ == '__main__':
    main()
