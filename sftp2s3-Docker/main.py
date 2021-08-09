import configparser
import subprocess
import os
import boto3
import base64
from botocore.exceptions import ClientError
import json


def get_secret(secretstore):

    secret_name = secretstore
    region_name = "cn-north-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret


# Get the Job classified information from Secrets Manager
secret_name = os.getenv("SecretName")
secretResult = get_secret(secret_name)
#print(secretResult)
#print(type(secretResult))
secretDict = json.loads(secretResult)
aws_ak = secretDict["access_key_id"]
aws_sk = secretDict["secret_access_key"]
sftp_pass = secretDict["sftp_password"]
sftp_priv_key = secretDict["sftp_private_key"]


# Copy the JobConf into Container
region = os.getenv("Region")
rconf = "s3://" + os.getenv("JobConf")
subprocess.run(['mkdir', '-p', '/root/.config/rclone'])
subprocess.run(['aws', '--region', region ,'s3', 'cp', rconf, '/root/.config/rclone/rclone.conf'])

## Update the sftp password or private key file
if sftp_pass != "Replace Me using your sftp password":
    result = subprocess.run(['/usr/bin/rclone', 'config', 'password', 'src-sftp', 'pass', sftp_pass])
    if result.returncode != 0:
        print("Update password was failed")

# Update rclone remote system's attribute
conf = configparser.ConfigParser()
rfp=conf.read("/root/.config/rclone/rclone.conf")

# update the sftp private_key
if sftp_priv_key == "Replace Me using your aws access secret key":
    conf["src-sftp"]["key_pem"] = ""
else:        
    conf["src-sftp"]["key_pem"] = sftp_priv_key

## Update the s3 ak&sk
conf["dst-s3"]["access_key_id"] = aws_ak
conf["dst-s3"]["secret_access_key"] = aws_sk

# Read the Replication
srcpath = conf["Replication"]["src_path"]
dstpath = conf["Replication"]["dst_path"]

# Save the configuration
with open('/root/.config/rclone/rclone.conf', 'w') as configfile:
    conf.write(configfile)

#print("Review the rclone.conf")
#subprocess.run(['cat','/root/.config/rclone/rclone.conf'])

# Replicate the data from the sftp source to the S3 destination
subprocess.run(["/usr/bin/rclone", "copyto", "src-sftp:" + srcpath, "dst-s3:" + dstpath, "-P", "--transfers", "16", "--checkers", "16"])
