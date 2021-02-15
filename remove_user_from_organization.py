#!/bin/bash/env python3
""" 
remove_user_from_organization.py3
A script to remove a user from various tools that Groundtruth leverages 
"""

__author___ = "Reuben deVries"
__version__ = "0.1"

# Importing python built-in libraries

import os
import argparse
import json
import requests
import base64
import sys

# Importing python 3rd party libraries

import boto3
import botocore

class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'

def remove_iam_user(awsuser):
    
    """ 
    Function used to remove IAM Users throughly, will remove the ability to login
    detach any policies directly attached to their IAM account. Remove the IAM user
    from any existing groups. Remove any Access Keys, Remove any public SSH keys so they 
    can no longer commit to repositories in Code Commit, disables MFA and finally deletes
    the user.
    """

    iam_client = boto3.client('iam')
    iam = boto3.resource('iam')
    user = iam.User(awsuser)
    try:
        user.load()
        print(bcolors.OKGREEN + f"Removing AWS IAM User: {user}")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print(bcolors.WARNING + f"{user} does not exist in our AWS Account")
            return
        else:
            raise e
    try:
        print(bcolors.OKGREEN + f"Removing the LoginProfile for AWS IAM user: {user}")
        login_profile = iam.LoginProfile(user.name)
        login_profile.load()
        login_profile.delete()
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
           print(bcolors.WARNING + f"{user} does not have access to the AWS Console")
        else:
           raise e
    print(bcolors.OKGREEN + f"Removing all policies directly attached to {user}")
    for policy in user.attached_policies.all():
        policy.detach_user(UserName=user.name)

    print(bcolors.OKGREEN + f"Removing {user} from all IAM Groups")
    for group in user.groups.all():
        group.remove_user(UserName=user.name)
    
    print(bcolors.OKGREEN + f"Removing any access keys attached to {user}")
    for access_key in user.access_keys.all():
        access_key.delete()

    print(bcolors.OKGREEN + f"Removing any public SSH Keys attached to {user} IAM account")
    resp = iam_client.list_ssh_public_keys(UserName=user.name)
    for key_id in [i.get("SSHPublicKeyId") for i in resp.get("SSHPublicKeys", [])]:
        iam_client.delete_ssh_public_key(
        UserName=user.name,
        SSHPublicKeyId=key_id
        )

    for device in user.mfa_devices.all():
        print(bcolors.OKGREEN + f"Remove any MFA devices attached to {user}")
        device.disassociate()
    
    try:
        user.delete()
        print(bcolors.OKGREEN + f"IAM User: {user} was sucessfully removed.")
    except botocore.exceptions.ClientError as e:
        raise SystemExit(bcolors.WARNING + f"unable to delete IAM user: {user}\nCause: {e.response['Error']['Code']}")
        
def get_secret():
    
    """ 
    Function used to retrieve the VictorOps-API secret api key
    See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html 
    """
    
    secret_name = "VictorOps-API"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name = 'secretsmanager',
        region_name = region_name
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
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    return json.loads(secret) #This returns a dictionary with the API ID & Key.

def remove_user_from_victor_ops(vouser,volead):
    
    """ 
    Function used to remove the victor ops user from the rotation and replace their rotation 
    with the team lead or someone else 
    """
    
    vo_user = args.vouser
    vo_lead = args.volead
    url = f"https://api.victorops.com/api-public/v1/user/{vo_user}/"
    headers = {'Content-Type': 'application/json', 'Accept':'text/plain'}
    payload = {f"replacement":"{vo_lead}"}
#       Appending additional headers to the existing dictionary containing
#       the API secrets 'X-VO-Api-Id' & 'X-VO-Api-Key'.
    try:
        headers.update(get_secret())
        response = requests.delete(url, headers=headers, params=payload)
        print(bcolors.OKGREEN + f"user {vo_user} has been deleted from the Victor Ops System","green")
    except botocore.exceptions.ClientError as e:
        raise e

def get_token():
    
    """ 
    Function used to retrieve the GitHub secret api key
    See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html 
    """

    secret_name = "GitHub-API"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name = 'secretsmanager',
        region_name = region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId = secret_name
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
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
    return json.loads(secret)

def remove_user_from_github(ghuser):
    
    """ 
    Function used to remove the user from the @xadrnd GitHub Organization 
    """

    gh_user = args.ghuser
    url = f"https://api.github.com/orgs/xadrnd/memberships/{gh_user}"
    access_token = get_token()
    print(url, access_token)
#       Appending additional headers to the existing dictionary containing
#       the API secrets 'X-VO-Api-Id' & 'X-VO-Api-Key'.
    try:
       response = requests.delete(url, headers=access_token)

    except botocore.exceptions.ClientError as e:
       raise e

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Passing some data that you want "
                                 "to use for variable into this script")
    parser.add_argument("-a", "--awsuser",
                    help="Add the username of the user you wish to remove from AWS IAM.")
    parser.add_argument("-v","--vouser",
                        help="the username of the user you wish to remove from VictorOps.")
    parser.add_argument("-l","--volead",
                        help="the username of the team leader who will replace the user's oncall.")
    parser.add_argument("-g","--ghuser",
                        help="the username of the user you wish to remove from your github organization.")
    args = parser.parse_args()

    remove_iam_user(args.awsuser)
    get_secret()
    remove_user_from_victor_ops(args.vouser,args.volead)
    get_token()
    remove_user_from_github(args.ghuser)
