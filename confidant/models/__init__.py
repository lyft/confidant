from confidant.app import app
from confidant.utils.dynamodb import create_dynamodb_tables

if app.config['DYNAMODB_CREATE_TABLE']:
    create_dynamodb_tables()
