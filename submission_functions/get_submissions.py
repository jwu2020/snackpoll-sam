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
    result = []
    try:
        print(conn)
        with conn.cursor() as cur:
            cur.execute(query)
            for row in cur:
                result.append(row)
    except Exception as e:
        # Error while opening connection or processing
        print(e)
    return result


def enrich_list(headers_list, result_list):
    """
    Combine the headers list and the list of sql results

    Return: list of dictionaries with SQL cells mapped to their headers
    """

    if len(headers_list) != len(result_list[0]):
        print("Length of headers must be the same as the result columns")
        return

    result_dict = []

    for row in result_list:
        entry = {}
        for i in range(len(headers_list)):
            entry[headers_list[i][0]] = row[i]
        result_dict.append(entry)

    return result_dict


def format_response(code, body):
    return {
        "statusCode": code,
        "body": json.dumps(body),
        "headers": {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT'
        },

    }


def lambda_handler(event, context):
    print(event, context)
    logging.basicConfig(level=logging.INFO)

    # sql_query = event['sql_query']
    # table = event['table']

    sql_query = event['queryStringParameters']['sql_query']
    table = event['queryStringParameters']['table']

    print(f"sql: {sql_query}")
    print(f"table: {table}")
    db_name = os.environ['RDS_DB_NAME']
    secret_name = os.environ['SECRET_NAME']
    db_region_name = os.environ['DB_REGION']

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
    sql_res = run_query(sql_query)

    if table != "":
        header_query = f"SELECT `COLUMN_NAME` FROM `INFORMATION_SCHEMA`.`COLUMNS` WHERE `TABLE_SCHEMA`='{db_name}' AND `TABLE_NAME`='{table}';"
        headers = run_query(header_query)
        sql_res = enrich_list(headers, sql_res)

        logging.info(f'Headers result: {headers}')
    print(f'SQL Query result: {sql_res}')

    print("Closing Connection")
    if (conn is not None and conn.open):
        conn.close()

    return format_response(200, sql_res)

