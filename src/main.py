#!/usr/bin/env python3
import boto3
import argparse
import configparser
import logging
import json
from os.path import expanduser
import colorama
from colorama import Fore, Style

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
LOGGER = logging.getLogger(__name__)

DEFAULT_CREDENTIALS_FILE = f'{expanduser("~")}/.aws/credentials'
SESSION = None


def get_args()->dict:
    parser = argparse.ArgumentParser(description='AWS Assume Role elevation')
    parser.add_argument('-p', '--profile', type=str, help='Default AWS profile')
    parser.add_argument('-A', '--assume_role', type=str, help='role name or ARN to assume')
    parser.add_argument('-S', '--duration_seconds',
                        type=int,
                        default=3600,
                        help='assume role duration seconds in seconds')
    parser.add_argument(
        '-C', '--credentials_file',
        type=str,
        default=DEFAULT_CREDENTIALS_FILE,
        help=f'OPTIONAL: absolute path to aws credentials file (default: {DEFAULT_CREDENTIALS_FILE})'
    )

    return parser.parse_args()


def prompt_options(options:list, color_text:int=Fore.WHITE, color_highlight:int=Fore.CYAN, question:str=None):
    if not question:
        question = f'{color_text}Chose one (enter a number): {Fore.RESET}'
    i = 0
    for o in options:
        print(f'{color_text}{i}) {color_highlight}{o}{Style.RESET_ALL}')
        i += 1
    choice = int(input(question) or 0)
    return options[choice]

def get_role_policies(role_name: str, policies: list = [], marker: str = ''):
    global SESSION

    iam_client = SESSION.client('iam')
    if marker:
        response = iam_client.list_role_policies(RoleName=role_name,
                                                 Marker=marker)
    else:
        response = iam_client.list_role_policies(RoleName=role_name)

    for policy_name in response['PolicyNames']:
        policies.append(iam_client.get_role_policy(PolicyName=policy_name,
                                          RoleName=role_name)['PolicyDocument'])

    if response['IsTruncated']:
        return get_role_policies(role_name, policies=policies,
                                 marker=response['Marker'])
    return policies

def get_roles(roles:list=[], marker:str=''):
    global SESSION

    iam_client = SESSION.client('iam')
    if marker:
        response = iam_client.list_roles(Marker=marker)
    else:
        response = iam_client.list_roles()

    roles += response['Roles']
    if response['IsTruncated']:
        return get_roles(roles=roles, marker=response['Marker'])
    return roles


def main(args: dict):
    global SESSION

    config = configparser.RawConfigParser()
    with open(args.credentials_file, 'r') as f:
        config.read_file(f)
        sections: list = config.sections()
    if args.profile:
        profile = args.profile
    else:
        profile: str = prompt_options(sections)

    LOGGER.info(f'Using AWS profile: {Fore.GREEN}{profile}{Fore.RESET}')
    role_session_name = f'{profile}-{args.assume_role}'
    if profile == 'default':
        SESSION = boto3.Session()
    else:
        SESSION = boto3.Session(profile_name=profile)

    sts_client = SESSION.client('sts')
    aws_account_id = sts_client.get_caller_identity()['Account']
    if args.assume_role:
        role_arn = args.assume_role
        if not args.assume_role.startswith('arn:aws:'):
            role_arn = f'arn:aws:iam::{aws_account_id}:role/{args.assume_role}'

        LOGGER.info(f'Assuming role [{role_arn}] in account {aws_account_id}')
        assumedRoleObject = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=role_session_name,
            DurationSeconds=args.duration_seconds)
        credentials: dict = assumedRoleObject['Credentials']
        SESSION = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'])
        LOGGER.info(f'Expiration: {credentials["Expiration"]}')

    role = get_roles()[0]
    # for role in get_roles():
    policies = get_role_policies(role['RoleName'])
    LOGGER.info(role['RoleName'])
    LOGGER.info(role['AssumeRolePolicyDocument'])
    LOGGER.info(role['PermissionsBoundary'] if 'PermissionsBoundary' in role else '')
    print(json.dumps(policies, indent=2))



if __name__ == "__main__":
    main(get_args())
