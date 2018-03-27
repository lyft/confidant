from confidant.app import app
from confidant.models.blind_credential import BlindCredential
from confidant.models.credential import Credential
from confidant.models.service import Service

from flask.ext.script import Command, Option
import logging
import sys
import time

from botocore.exceptions import ClientError
from pynamodb.exceptions import UpdateError
from pynamodb.expressions.operand import Path


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


def _handleUpdateException(e, item):
    """
    Handle exceptions of type update.
    """
    if not isinstance(e.cause, ClientError):
        raise e
    code = e.cause.response['Error'].get('Code')
    if code == 'ConditionalCheckFailedException':
        app.logger.warn(
            'conditional update failed (concurrent writes?) for object:'
            ' (you will need to re-run migration)'
        )
        return True
    if code == 'ProvisionedThroughputExceededException':
        app.logger.warn('provisioned write capacity exceeded at object:'
                        ' backing off (you will need to re-run migration)')
        return True
    raise e


def migrate_boolean_attributes(model_class,
                               model_name,
                               attribute_names,
                               mock_conditional_update_failure=False,
                               limit=None,
                               number_of_secs_to_back_off=1,
                               max_items_updated_per_second=1.0):
    """
    Migrates boolean attributes per GitHub
    `issue 404 <https://github.com/pynamodb/PynamoDB/issues/404>`_.
    Will scan through all objects and perform a conditional update
    against any items that store any of the given attribute names as
    integers.
    Note that updates require provisioned write capacity as
    well. Please see `the DynamoDB docs
    <http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks
    .ProvisionedThroughput.html>`_
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
    :param model_class: The Model class for which you are migrating. This
                        should be the up-to-date Model class using a
                        BooleanAttribute for the relevant attributes.
    :param model_name: The name of the model. It must correspond to the
                       model_class, e.g. BlindCredential = blind_credential,
                       Credential = credential, Service = service.
    :param attribute_names: List of strings that signifiy the names of
                            attributes which are potentially in need of
                            migration.
    :param mock_conditional_update_failure: Only used for unit testing. When
                                            True, the conditional update
                                            expression used internally is
                                            updated such that it is guaranteed
                                            to fail. This is meant to trigger
                                            the code path in boto, to allow us
                                            to unit test that we are jumping
                                            through appropriate hoops handling
                                            the resulting failure and
                                            distinguishing it from other
                                            failures.
    :param limit: Passed along to the underlying 'limit'. Used to limit the
                  number of results returned.
    :param number_of_secs_to_back_off: Number of seconds to sleep when
                                       exceeding capacity.
    :param max_items_updated_per_second: An upper limit on the rate of items
                                         update per second.
    :return: (number_of_items_in_need_of_update,
              number_of_them_that_failed_due_to_conditional_update)
    """
    app.logger.info('migrating items; no progress will be reported until '
                    'completed; this may take a while')
    num_items_with_actions = 0
    num_update_failures = 0
    items_processed = 0
    time_of_last_update = 0.0
    if max_items_updated_per_second <= 0.0:
        raise ValueError(
            'max_items_updated_per_second must be greater than zero'
        )

    for item in model_class.data_type_date_index.query(model_name):
        items_processed += 1
        if items_processed % 1000 == 0:
            app.logger.info(
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
            if _handleUpdateException(e, item):
                num_update_failures += 1
                # In case of throttling, back off amount of seconds before
                # continuing
                time.sleep(number_of_secs_to_back_off)

    app.logger.info(
        'finished migrating; {} items required updates'.format(
            num_items_with_actions
        )
    )
    app.logger.info(
        '{} items failed due to racing writes and/or exceeding capacity and '
        'require re-running migration'.format(num_update_failures)
    )
    return num_items_with_actions, num_update_failures


class MigrateBooleanAttribute(Command):

    option_list = (
        Option(
            '--model',
            action="store",
            dest="model_name",
            type=str,
            required=True,
            help='The model that should be migrated. Choose from service, '
                 'blind_credential or credential'
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
        )
    )

    def run(self, model_name, limit, back_off, update_rate):
        attributes = ['enabled']
        app.logger.info('Model: {}, Limit: {}, Back off: {}, '
                        'Max update rate: {}, Attributes: {}'.format(
                            model_name, limit, back_off, update_rate,
                            attributes
                        ))
        app.logger.info('Working on model: {}'.format(model_name))
        if model_name == 'service':
            model = Service
        elif model_name == 'credential':
            model = Credential
        elif model_name == 'blind_credential':
            model = BlindCredential
        else:
            raise Exception('Invalid model: {}'.format(model_name))
        res = migrate_boolean_attributes(
            model,
            model_name,
            attributes,
            limit=limit,
            number_of_secs_to_back_off=back_off,
            max_items_updated_per_second=update_rate
        )
        app.logger.info(res)
