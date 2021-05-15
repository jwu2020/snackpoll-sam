# This lambda will execute any SQL query from the RDS MSQL.

import boto3
import base64
from botocore.exceptions import ClientError
import json
import os
import pymysql
import traceback

conn = None

def get_db_details(secret_name, db_region_name):
    """
    Grab the DB password from the Secrets Manager
    """

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=db_region_name
    )
    print("Connected to secrets manager service")
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name)
        print(get_secret_value_response)
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            traceback.print_exc()
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            traceback.print_exc()
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            traceback.print_exc()
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            traceback.print_exc()
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            traceback.print_exc()
        return
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret

def conn_rdb(rds_host, username, password, db_name):
    """
    Establish a connection with the RDS host.
    """

    global conn
    print("In Open connection")

    try:
        conn = pymysql.connect(
            host=rds_host,
            user=username,
            password=password,
            db=db_name,
            connect_timeout=15)

    except Exception as e:
        traceback.print_stack()
        print(e)
        print("ERROR: Unexpected error: Could not connect to MySql instance.")
        return None

def put_query(query):
    """
    Run a put query on RDS
    """
    try:
        mycursor = conn.cursor()
        mycursor.execute(query)
        conn.commit()
        mycursor.close()
        return {"code": 200, "message": "Updated database successfully"}
    except Exception as e:
        # Error while opening connection or processing
        print(e)
        return {"code": 500, "message": f"Could not update database successfully. Error: {e}"}

def get_query(query):
    """
    Run a query on RDS
    Return: List, each entry is an one SQL result.
    """
    try:
        mycursor = conn.cursor()
        mycursor.execute(query)
        conn.commit()
        mycursor.close()
        return {"code": 200, "message": "Updated database successfully"}
    except Exception as e:
        # Error while opening connection or processing
        print(e)
        return {"code": 500, "message": f"Could not update database successfully. Error: {e}"}

def check_table_exists(db_name, table_name):
    sql_query = f"SELECT * FROM information_schema.tables WHERE table_schema = '{db_name}'  AND table_name = '{table_name}' LIMIT 1;"
    res = get_query(sql_query)

    # If table doesn't exist, create and populate table
    try:
        if not res:
            print("Initialising table")
            create_table_query = f"CREATE TABLE {table_name} (name VARCHAR(100), upvote INT, downvote INT, submitted_by VARCHAR(100));"
            get_query(create_table_query)

            populate_table_query = f"INSERT INTO {table_name} VALUES ('Bananas', 1, 0, 'Jess');"
            put_query(populate_table_query)

        return True
    except Exception as e:
        traceback.print_stack()
        print(e)
        return False

def format_response(code, body):
    return {
        "statusCode": code,
        "body": json.dumps(body),
        "headers": {
            'Content-Type': 'application/json',
        }
    }


def lambda_handler(event, context):
    print(event, context)

    snack_name = json.loads(event['body'])['name']
    table = json.loads(event['body'])['table']
    submitted_by = json.loads(event['body'])['submitted_by']
    db_name = os.environ['RDS_DB_NAME']
    secret_name = os.environ['SECRET_NAME']
    db_region_name = os.environ['DB_REGION']
    rds_host = os.environ['RDS_HOST']

    # Build query
    sql_query = f"INSERT INTO {table} VALUES ('{snack_name}', 1, 0, '{submitted_by}')"
    print(f"SQL query: {sql_query}\n DB: {db_name}\n Secret name: {secret_name}")

    # Get secrets
    rds_response = get_db_details(secret_name, db_region_name)
    if rds_response is None:
        return format_response(500, "Can't connect to Secrets Manager")
    rds_dict = json.loads(rds_response)
    username = rds_dict['username']
    password = rds_dict['password']

    # Connect to DB
    conn_rdb(rds_host, username, password, db_name)
    if conn is None:
        return format_response(500, "Can't connect to RDS")
    print("SUCCESS: Connection to RDS MySQL instance succeeded")

    # Set up table if it doesn't exist yet
    res = check_table_exists(db_name, table)
    if not res:
        return format_response(500, "Can't initialise table in RDS")

    # Run query
    resp = put_query(sql_query)
    print("Closing Connection")
    conn.close()

    return format_response(resp['code'], resp['message'])

