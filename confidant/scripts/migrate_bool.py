import logging
import time
import sys

from flask_script import Command, Option
from botocore.exceptions import ClientError
from pynamodb.exceptions import UpdateError
from pynamodb.expressions.operand import Path
from pynamodb.attributes import (
    UnicodeAttribute,
    BooleanAttribute,
)
from pynamodb.models import Model

from confidant import settings

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.INFO)


class GenericCredential(Model):
    class Meta:
        table_name = settings.DYNAMODB_TABLE
        if settings.DYNAMODB_URL:
            host = settings.DYNAMODB_URL
        region = settings.AWS_DEFAULT_REGION
        connect_timeout_seconds = settings.PYNAMO_CONNECT_TIMEOUT_SECONDS
        read_timeout_seconds = settings.PYNAMO_READ_TIMEOUT_SECONDS
        max_pool_connection = settings.PYNAMO_CONNECTION_POOL_SIZE
    id = UnicodeAttribute(hash_key=True)
    enabled = BooleanAttribute(default=True)


def _build_lba_filter_condition(attribute_names):
    """
    Build a filter condition suitable for passing to scan/rate_limited_scan,
    which will filter out any items for which none of the given attributes have
    native DynamoDB type of 'N'.
    """
    int_filter_condition = None
    for attr_name in attribute_names:
        if int_filter_condition is None:
            int_filter_condition = Path(attr_name).is_type('N')
        else:
            int_filter_condition |= Path(attr_name).is_type('N')

    return int_filter_condition


def _build_actions(model_class, item, attribute_names):
    """
    Build a list of actions required to update an item.
    """
    actions = []
    condition = None
    for attr_name in attribute_names:
        if not hasattr(item, attr_name):
            raise ValueError(
                'attribute {0} does not exist on model'.format(attr_name)
            )
        old_value = getattr(item, attr_name)
        if old_value is None:
            continue
        if not isinstance(old_value, bool):
            raise ValueError(
                'attribute {0} does not appear to be a boolean '
                'attribute'.format(attr_name)
            )

        actions.append(getattr(model_class, attr_name).set(
            getattr(item, attr_name))
        )

        if condition is None:
            condition = Path(attr_name) == (1 if old_value else 0)
        else:
            condition = condition & Path(attr_name) == (1 if old_value else 0)
    return actions, condition


def _handle_update_exception(e, item):
    """
    Handle exceptions of type update.
    """
    if not isinstance(e.cause, ClientError):
        raise e
    code = e.cause.response['Error'].get('Code')
    if code == 'ConditionalCheckFailedException':
        logger.warning(
            'conditional update failed (concurrent writes?) for object:'
            ' (you will need to re-run migration)'
        )
        return True
    if code == 'ProvisionedThroughputExceededException':
        logger.warning(
            'provisioned write capacity exceeded at object:'
            ' backing off (you will need to re-run migration)'
        )
        return True
    raise e


def migrate_boolean_attributes(model_class,
                               attribute_names,
                               read_capacity_to_consume_per_second=10,
                               allow_scan_without_rcu=False,
                               mock_conditional_update_failure=False,
                               page_size=None,
                               limit=None,
                               number_of_secs_to_back_off=1,
                               max_items_updated_per_second=1.0):
    """
    Migrates boolean attributes per GitHub
    `issue 404 <https://github.com/pynamodb/PynamoDB/issues/404>`_.
    Will scan through all objects and perform a conditional update
    against any items that store any of the given attribute names as
    integers. Rate limiting is performed by passing an appropriate
    value as ``read_capacity_to_consume_per_second`` (which defaults to
    something extremely conservative and slow).
    Note that updates require provisioned write capacity as
    well. Please see `the DynamoDB docs
    <http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/
    HowItWorks.ProvisionedThroughput.html>`_
    for more information. Keep in mind that there is not a simple 1:1
    mapping between provisioned read capacity and write capacity. Make
    sure they are balanced. A conservative calculation would assume
    that every object visted results in an update.
    The function with log at level ``INFO`` the final outcome, and the
    return values help identify how many items needed changing and how
    many of them succeed. For example, if you had 10 items in the
    table and every one of them had an attribute that needed
    migration, and upon migration we had one item which failed the
    migration due to a concurrent update by another writer, the return
    value would be: ``(10, 1)``
    Suggesting that 9 were updated successfully.
    It is suggested that the migration step be re-ran until the return
    value is ``(0, 0)``.
    :param model_class:
        The Model class for which you are migrating. This should be the
        up-to-date Model class using a BooleanAttribute for the relevant
        attributes.
    :param attribute_names:
        List of strings that signifiy the names of attributes which are
        potentially in need of migration.
    :param read_capacity_to_consume_per_second:
        Passed along to the underlying `rate_limited_scan` and intended as the
        mechanism to rate limit progress. Please see notes below around write
        capacity.
    :param allow_scan_without_rcu:
        Passed along to `rate_limited_scan`; intended to allow unit tests to
        pass against DynamoDB Local.
    :param mock_conditional_update_failure:
        Only used for unit testing. When True, the conditional update
        expression used internally is updated such that it is guaranteed to
        fail. This is meant to trigger the code path in boto, to allow us to
        unit test that we are jumping through appropriate hoops handling the
        resulting failure and distinguishing it from other failures.
    :param page_size:
        Passed along to the underlying 'page_size'. Page size of the scan to
        DynamoDB.
    :param limit:
        Passed along to the underlying 'limit'. Used to limit the number of
        results returned.
    :param number_of_secs_to_back_off:
        Number of seconds to sleep when exceeding capacity.
    :param max_items_updated_per_second:
        An upper limit on the rate of items update per second.
    :return: (number_of_items_in_need_of_update,
              number_of_them_that_failed_due_to_conditional_update)
    """
    logger.info(
        'migrating items; no progress will be reported until '
        'completed; this may take a while'
    )
    num_items_with_actions = 0
    num_update_failures = 0
    items_processed = 0
    time_of_last_update = 0.0
    if max_items_updated_per_second <= 0.0:
        raise ValueError(
            'max_items_updated_per_second must be greater than zero'
        )

    for item in model_class.rate_limited_scan(
            _build_lba_filter_condition(attribute_names),
            read_capacity_to_consume_per_second=(
                read_capacity_to_consume_per_second
            ),
            page_size=page_size,
            limit=limit,
            allow_rate_limited_scan_without_consumed_capacity=(
                allow_scan_without_rcu
            )):
        items_processed += 1
        if items_processed % 1000 == 0:
            logger.info(
                'processed items: {} Thousand'.format(items_processed/1000)
            )

        actions, condition = _build_actions(model_class, item, attribute_names)

        if not actions:
            continue

        if mock_conditional_update_failure:
            condition = condition & (Path('__bogus_mock_attribute') == 5)

        try:
            num_items_with_actions += 1
            # Sleep amount of time to satisfy the maximum items updated per sec
            # requirement
            time.sleep(
                max(0, 1 / max_items_updated_per_second - (
                    time.time() - time_of_last_update
                ))
            )
            time_of_last_update = time.time()
            item.update(actions=actions, condition=condition)
        except UpdateError as e:
            if _handle_update_exception(e, item):
                num_update_failures += 1
                # In case of throttling, back off amount of seconds before
                # continuing
                time.sleep(number_of_secs_to_back_off)

    logger.info(
        'finished migrating; {} items required updates'.format(
            num_items_with_actions
        )
    )
    logger.info(
        '{} items failed due to racing writes and/or exceeding capacity and '
        'require re-running migration'.format(num_update_failures)
    )
    return num_items_with_actions, num_update_failures


class MigrateBooleanAttribute(Command):

    option_list = (
        Option(
            '--RCU',
            action="store",
            dest="RCU",
            type=int,
            default=10,
            help='Read Capacity Units to be used for scan method.'
        ),
        Option(
            '--page-size',
            action="store",
            dest="page_size",
            type=int,
            default=None,
            help='Page size used in the scan.'
        ),
        Option(
            '--limit',
            action="store",
            dest="limit",
            type=int,
            default=None,
            help='Limit the number of results returned in the scan.'
        ),
        Option(
            '--back-off',
            action="store",
            dest="back_off",
            type=int,
            default=1,
            help='Number of seconds to sleep when exceeding capacity.'
        ),
        Option(
            '--update-rate',
            action="store",
            dest="update_rate",
            type=float,
            default=1.0,
            help='An upper limit on the rate of items update per second.'
        ),
        Option(
            '--scan-without-rcu',
            action="store_true",
            dest="scan_without_rcu",
            default=False,
            help='For development purposes, allow scanning without read '
                 'capacity units'
        )
    )

    def run(self, RCU, page_size, limit, back_off, update_rate,
            scan_without_rcu):
        attributes = ['enabled']
        logger.info(
            'RCU: {}, Page Size: {}, Limit: {}, Back off: {}, '
            'Max update rate: {}, Attributes: {}'.format(
                RCU, page_size, limit, back_off, update_rate,
                attributes
            )
        )
        model = GenericCredential
        res = migrate_boolean_attributes(
            model,
            attributes,
            read_capacity_to_consume_per_second=RCU,
            page_size=page_size,
            limit=limit,
            number_of_secs_to_back_off=back_off,
            max_items_updated_per_second=update_rate,
            allow_scan_without_rcu=scan_without_rcu
        )
        logger.info(res)
