import logging
import boto3

from confidant import settings

def init_logging():
    logging.getLogger(__name__).info('Initializing logging')
    if not settings.get('DEBUG'):
        boto3.set_stream_logger(level=logging.CRITICAL)
        logging.getLogger('botocore').setLevel(logging.CRITICAL)
        logging.getLogger('pynamodb').setLevel(logging.WARNING)


def get_logger(name=__name__):
    return logging.getLogger(name)


def logging_abstraction(log_level='INFO', msg='', name=__name__):
    logger = get_logger(name)

    if log_level == 'INFO' and msg:
        logger.info(msg)
    elif log_level == 'ERROR' and msg:
        logger.error(msg)
    elif log_level == 'DEBUG' and msg:
        logger.debug(msg)
    elif log_level == 'CRITICAL' and msg:
        logger.critical(msg)
    elif log_level == 'WARNING' and msg:
        logger.warning(msg)
