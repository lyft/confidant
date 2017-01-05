"""Module for accessing services external to Confidant."""

import boto3
import logging

CLIENT_CACHE = {}
RESOURCE_CACHE = {}


def get_boto_client(
        client,
        region=None,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_session_token=None,
        config=None
        ):
    """Get a boto3 client connection."""
    if config is None:
        config = {}
    cache_key = '{0}:{1}:{2}:{3}'.format(
        client,
        region,
        aws_access_key_id,
        config.get('name')
    )
    if not aws_session_token:
        if cache_key in CLIENT_CACHE:
            return CLIENT_CACHE[cache_key]
    session = get_boto_session(
        region,
        aws_access_key_id,
        aws_secret_access_key,
        aws_session_token
    )
    if not session:
        logging.error("Failed to get {0} client.".format(client))
        return None

    CLIENT_CACHE[cache_key] = session.client(
        client,
        config=config.get('config')
    )
    return CLIENT_CACHE[cache_key]


def get_boto_resource(
        resource,
        region=None,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_session_token=None,
        config=None
        ):
    """Get a boto resource connection."""
    if config is None:
        config = {}
    cache_key = '{0}:{1}:{2}:{3}'.format(
        resource,
        region,
        aws_access_key_id,
        config.get('name')
    )
    if not aws_session_token:
        if cache_key in RESOURCE_CACHE:
            return RESOURCE_CACHE[cache_key]
    session = get_boto_session(
        region,
        aws_access_key_id,
        aws_secret_access_key,
        aws_session_token
    )
    if not session:
        logging.error("Failed to get {0} resource.".format(resource))
        return None

    RESOURCE_CACHE[cache_key] = session.resource(
        resource,
        config=config.get('config')
    )
    return RESOURCE_CACHE[cache_key]


def get_boto_session(
        region,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_session_token=None
        ):
    """Get a boto3 session."""
    return boto3.session.Session(
        region_name=region,
        aws_secret_access_key=aws_secret_access_key,
        aws_access_key_id=aws_access_key_id,
        aws_session_token=aws_session_token
    )
