import sys
import logging
from flask_script import Command

from confidant.app import app
from confidant.utils.dynamodb import create_dynamodb_tables

app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.INFO)


class CreateDynamoTables(Command):
    """
    Setup dynamo tables
    """
    def run(self):
        create_dynamodb_tables()
