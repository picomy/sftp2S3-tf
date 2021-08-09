import json
import boto3
import logging 

# Import Boto 3 for AWS Glue
import boto3
client = boto3.client('glue')

# Variables for the job: 
logger =logging.getLogger()

def lambda_handler(event, context):
    # TODO implement
    logger.info('## TRIGGERED BY EVENT: ',event)
    logger.info(event)
    response = client.start_crawler(Name=event["JOB"])
    logger.info('## GLUE JOB RUN ID: ' + response['JobRunId'])
    return {
        'statusCode': 200
    }
