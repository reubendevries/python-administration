#!/bin/bash/env python3
""" 
remove_user_from_organization
A script to remove a user from various tools
"""

__author___ = "Reuben deVries"
__version__ = "0.1"

# Importing python built-in libraries

import argparse
import json
import base64

# Importing python 3rd party libraries

import boto3
import botocore.exceptions
import requests

class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'

def remove_iam_user(email):
    """ 
    Function used to remove IAM Users throughly, will remove the ability to login
    detach any policies directly attached to their IAM account, removes the IAM user
    from any existing groups, removes any Access Keys, removes any public SSH keys, disables MFA and finally deletes
    the user.
    """
    iam = boto3.client('iam')

    try:
        get_user = iam.get_user(
            UserName = email
        )
        user = get_user["User"]["UserName"]
        print(bcolors.OKGREEN + "Removing AWS IAM User: {}".format(user))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "NoSuchEntity":
            print(bcolors.WARNING + "{} does not exist in our AWS Account".format(user))
            return
        else:
            raise e
    try:
        print(bcolors.OKGREEN + "Removing the LoginProfile for AWS IAM user: {}".format(user))
        iam.delete_login_profile(
            UserName=user
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
           print(bcolors.WARNING + "{} does not have access to the AWS Console".format(user))
        else:
           raise e
    try:
        print(bcolors.OKGREEN + "Removing all policies directly attached to {}".format(user))
        attached_policies = iam.list_attached_user_policies(
            UserName=user
        )
        for policy_arn in attached_policies["AttachedPolicies"]:
                arn = policy_arn["PolicyArn"]
                iam.detach_user_policy(
                    UserName=user,
                    PolicyArn=arn
                )
                print(bcolors.OKGREEN + "dettaching {} from {}'s profile".format(arn, user))
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(bcolors.WARNING + "No Policies attached to {}'s profile".format(user))
        elif e.response["Error"]["Code"] == "InvalidInputException":
            print(bcolors.WARNING + "an invalid or out-of-range value was supplied for an input parameter")
        elif e.response["Error"]["Code"] == "LimitExceededException":
            print(bcolors.WARNING + "The request was rejected because it attempted to create resources beyond the current AWS account limits.")
        else:
            raise e
    try:
        print(bcolors.OKGREEN + "Removing {} from all IAM Groups".format(user))
        list_groups_for_user = iam.list_groups_for_user(
            UserName=user
        )

        for groups in list_groups_for_user["Groups"]:
            group_name = (groups["GroupName"])
            iam.remove_user_from_group(
                UserName=user,
                GroupName=group_name
            )
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(bcolors.WARNING + "No Groups attached to {}'s profile".format(user))
        elif e.response["Error"]["Code"] == "LimitExceededException":
            print(bcolors.WARNING + "The request was rejected because it attempted to create resources beyond the current AWS account limits.")
        else:
            raise e
    try:    
        print(bcolors.OKGREEN + "Removing any access keys attached to {}".format(user))
        list_access_keys = iam.list_access_keys(
            UserName=email
        )
        for key in list_access_keys["AccessKeyMetadata"]:
            access_key = (key["AccessKeyId"])
            iam.delete_access_key(
                UserName=email,
                AccessKeyId=access_key
            )
            print(bcolors.OKGREEN + "deleting {} from {}'s profile".format(access_key,email))
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(bcolors.WARNING + "No Access Keys attached to {}'s profile".format(user))
        elif e.response["Error"]["Code"] == "LimitExceededException":
            print(bcolors.WARNING + "The request was rejected because it attempted to create resources beyond the current AWS account limits.")
        else:
            raise e
    try:
        print(bcolors.OKGREEN + "Removing any public SSH Keys attached to {} IAM account".format(email))
        list_ssh_public_keys = iam.list_ssh_public_keys(
            UserName=user
        )
        for public_key in list_ssh_public_keys["SSHPublicKeys"]:
            public_key_id = public_key["SSHPublicKeyId"]
            iam.delete_ssh_public_key(
                UserName=user,
                SSHPublicKeyId=public_key_id
            )
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(bcolors.WARNING + "No Public SSH Keys attached to {}'s profile".format(user))
        else:
            raise e
    try:
        list_mfa_devices = iam.list_mfa_devices(
            UserName=user
        )
        for mfa_device in list_mfa_devices["MFADevices"]:
            serial_number = mfa_device["SerialNumber"]
            iam.deactivate_mfa_device(
                UserName=user,
                SerialNumber=serial_number
            )

        iam.delete_user(
            UserName=user
        )
        print(bcolors.OKGREEN + "IAM User: {} was sucessfully removed.".format(user))
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(bcolors.WARNING + "No MFA devices attached to {}'s profile".format(user)) 
        elif e.response["Error"]["Code"] == "LimitExceededException":
            print(bcolors.WARNING + "The request was rejected because it attempted to create resources beyond the current AWS account limits.")
        elif e.response["Error"]["Code"] == "EntityTemporarilyUnmodifiableException":
            print(bcolors.WARNING + "The request was rejected because it referenced an entity that is temporarily unmodifiable, such as a user name that was deleted and then recreated.")
        else:
            raise SystemExit(bcolors.WARNING + "unable to delete IAM user: {}\nCause: {e.response['Error']['Code']}".format(user))
        
def do_api_secret():
    
    """ 
    Function used to retrieve the Digital Ocean API key.
    See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html 
    """
    
    secret_name = "Digital-Ocean-API"
    region_name = "ca-central-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except botocore.exceptions.ClientError as e:
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
            do_api_key = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret
    return json.loads(do_api_key) #This returns a dictionary with the API ID & Key.

def remove_key_from_digital_ocean(do_api_key, email):
    secret_value = do_api_key['Digital_Ocean_API']
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer {}".format(secret_value)
    }
    api = "https://api.digitalocean.com"
    list_all_keys = "/v2/account/keys"
    url = api + list_all_keys
    all_keys = requests.get(url, headers=headers)
    response = json.loads(all_keys.text)
    for keys in response["ssh_keys"]:
        name = keys["name"]
        if name == email:
            fingerprint = keys["fingerprint"]
            destroy_key = "/v2/account/keys/{}".format(fingerprint)
            url = api + destroy_key
            requests.delete(url, headers=headers)
            print(bcolors.OKGREEN + "{}'s Public SSH Key was sucessfully deleted from Digital Ocean.".format(email))
        else:
            print(bcolors.WARNING + "{}'s Public SSH Key wasn't found in Digital Ocean.".format(email))

def gl_api_secret():
    secret_name = "Gitlab-DevNet-API"
    region_name = "ca-central-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager",
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "DecryptionFailureException":
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InternalServiceErrorException":
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InvalidParameterException":
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InvalidRequestException":
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "ResourceNotFoundException":
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if "SecretString" in get_secret_value_response:
            gl_api_key = get_secret_value_response["SecretString"]
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response["SecretBinary"])
            return decoded_binary_secret
    return json.loads(gl_api_key)

def remove_user_from_gitlab(gl_api_key, email):
    secret_value = gl_api_key["GitLab_DevNet_API"]
    headers = {
        "Authorization": "Bearer {}".format(secret_value)
    }
    api = "https://gitlab.coppertreeanalytics.com/api/v4/"
    list_all_users = "users"
    url = api + list_all_users
    all_users = requests.get(url, headers=headers)
    response = json.loads(all_users.text)
    for users in response:
        if users["email"] == email:
            user_id = users["id"]
            url = api + list_all_users + ":" + user_id
            requests.delete(url, headers=headers)
            print(bcolors.OKGREEN + "{} was sucessfully deleted from Gitlab.".format(email))
        else:
            print(bcolors.WARNING + "{} wasn't found inside of Gitlab, can't delete from system.".format(email))
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Passing some data that you want "
                                 "to use for variable into this script")
    parser.add_argument("-e", "--email",
                    help="pass through the email address of the user you wish to deactivate")
    args = parser.parse_args()
    remove_iam_user(args.email)
    do_api_key = do_api_secret()
    remove_key_from_digital_ocean(do_api_key, args.email)
    gl_api_key = gl_api_secret()
    remove_user_from_gitlab(gl_api_key, args.email)