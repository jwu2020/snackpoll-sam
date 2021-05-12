# This lambda will execute any SQL query from the RDS MSQL.

import boto3
import base64
from botocore.exceptions import ClientError
import json
import os
import pymysql
import logging
import time
import random
import logging
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


def conn_db(db_region_name, rds_host, username, password, db_name):
    """
    Establish a connection with the RDS host.
    """

    global conn
    print("In Open connection")

    try:
        if (conn is None):
            print(rds_host, username, password, db_name)
            conn = pymysql.connect(
                rds_host, user=username, passwd=password, db=db_name, connect_timeout=15)
            print(conn)
        elif (not conn.open):
            print(conn.open)
            conn = pymysql.connect(
                rds_host, user=username, passwd=password, db=db_name, connect_timeout=15)

    except Exception as e:
        print(e)
        print("ERROR: Unexpected error: Could not connect to MySql instance.")


def run_query(query):
    """
    Run a query on RDS
    Return: List, each entry is an one SQL result.
    """
    try:
        mycursor = conn.cursor()
        mycursor.execute(query)
        conn.commit()
        return {"code": 200, "message": "Updated database successfully"}
    except Exception as e:
        # Error while opening connection or processing
        print(e)
        return {"code": 500, "message": f"Could not update database successfully. Error: {e}"}


def format_response(code, body):
    return {
        "statusCode": code,
        "body": json.dumps(body),
        "headers": {
            'Content-Type': 'application/json',
        }
    }


def lambda_handler(event, context):
    logging.basicConfig(level=logging.INFO)

    snack_name = event["queryStringParameters"]['name']
    table = event["queryStringParameters"]['table']
    submitted_by = event["queryStringParameters"]['submitted_by']
    db_name = os.environ['RDS_DB_NAME']
    secret_name = os.environ['SECRET_NAME']
    db_region_name = os.environ['DB_REGION']

    # Build query
    sql_query = f"INSERT INTO {table} VALUES ('{snack_name}', 1, 0, '{submitted_by}')"

    # Get secrets
    rds_response = get_db_details(secret_name, db_region_name)
    if rds_response is None:
        return format_response(500, "Can't connect to Secrets Manager")
    rds_dict = json.loads(rds_response)
    rds_host = rds_dict['host']
    username = rds_dict['username']
    password = rds_dict['password']
    conn_db(db_region_name, rds_host, username, password, db_name)
    if conn is None:
        return format_response(500, "Can't connect to RDS")

    print("SUCCESS: Connection to RDS MySQL instance succeeded")

    # Run query
    resp = run_query(sql_query)

    print("Closing Connection")
    if (conn is not None and conn.open):
        conn.close()

    return format_response(resp['code'], resp['message'])

