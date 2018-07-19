# This script is used to automate IAM access key rotation and syncronize
# it with the password rotation schedule.  It does not actually rotate
# the keys instead it just expires the keys and sends the IAM user an
# email telling them to rotate the their own access keys
from __future__ import print_function
import logging
import os
import csv
import json
from time import sleep
import dateutil.parser
from datetime import datetime, timedelta, date

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def lambda_handler(event, context):

    logger.debug("Received event: " + json.dumps(event, sort_keys=True))

    # These should be passed in via Lambda Environment Variables
    try:
        DISABLE_KEYS = True if os.environ['DISABLE_KEYS'].lower() == 'true' else False
        SEND_REPORT = True if os.environ['SEND_REPORT'].lower() == 'true' else False
        SEND_EMAIL = True if os.environ['SEND_EMAIL'].lower() == 'true' else False
        SENDER_EMAIL = os.environ['SENDER_EMAIL']
        REPORT_TOPIC_ARN = os.environ['REPORT_TOPIC_ARN']
        GRACE_PERIOD = int(os.environ['GRACE_PERIOD'])
    except (KeyError, ValueError, Exception) as e:
        logger.error(e.response['Error']['Message'])

    max_age = get_max_password_age()  # password expiration setting
    credential_report = get_credential_report()

    aws_account_identity = get_aws_account_identity()  # either account name or id
    logger.debug('aws_account_identity: {}'.format(aws_account_identity))

    report = ''     # a report summary for account admins
    # Iterate over the credential report, use the report to determine password expiration
    # Then query for access keys, and use the key creation data to determine key expiration
    iam_client = boto3.client('iam')
    for row in credential_report:
        logger.debug('processing iam account: ' + row['user'])
        # Skip IAM Users without passwords (service accounts), root user should not have access keys
        if row['password_enabled'] != "true": continue
        user_notice = ''     # notices for the IAM users
        try:
            # IAM client will fail if root user contains active keys because list_access_keys
            # method will fail for root username '<root_account>'
            response = iam_client.list_access_keys(UserName=row['user'])
            logger.debug("list_access_key response: " + json.dumps(response, default = myconverter))
            for key in response['AccessKeyMetadata'] :
                logger.debug('processing access key: ' + key['AccessKeyId'])
                if key['Status'] == "Inactive" : continue
                days_till_expire = get_days_until_key_expires(key['CreateDate'], max_age)
                logger.debug('days_till_expire: ' + str(days_till_expire))
                if days_till_expire <= 0:  # key has expired
                    logger.debug('access key {}:{}:{} has expired'.
                                 format(aws_account_identity, row['user'], key['AccessKeyId']))
                    if DISABLE_KEYS:
                        disable_key(key['AccessKeyId'], row['user'])
                        logger.debug('deactivated access key {}:{}:{}'.
                                     format(aws_account_identity, row['user'], key['AccessKeyId']))
                        message = '\n\tYour access key {}:{} has been deactivated.' \
                                    .format(aws_account_identity, key['AccessKeyId'])
                        user_notice = user_notice + message
                        report = report + message

                    else:
                        logger.debug('warn about expired access key {}:{}:{}'.
                                     format(aws_account_identity, row['user'], key['AccessKeyId']))
                        message = '\n\tYour access key {}:{} has expired.' \
                                    .format(aws_account_identity, key['AccessKeyId'])
                        user_notice = user_notice + message
                        report = report + message

                elif days_till_expire < GRACE_PERIOD:
                    logger.debug('warn about expiring access key {}:{}:{}'.
                                 format(aws_account_identity, row['user'], key['AccessKeyId']))
                    user_notice = user_notice + \
                                       ('\n\tYou must rotate your access key {}:{} in {} days.'
                                        .format(aws_account_identity,
                                                key['AccessKeyId'],
                                                days_till_expire))

        except ClientError as e:
            logger.error(e.response['Error']['Message'])

        if user_notice != '' and SEND_EMAIL:     # email to iam users
            logger.debug("Emailing user " + row['user'])
            subject = "Credential Expiration Notice From AWS Account: {}".format(aws_account_identity)
            footer = '\n\tAWS account policy requires rotating keys every {} days.'.format(max_age)
            body = user_notice + footer
            email_user(SENDER_EMAIL, row['user'], subject, body)

    if report != '' and SEND_REPORT:      # send reports to an SNS topic
        logger.debug("Publishing report to " + REPORT_TOPIC_ARN)
        publish_sns_topic(REPORT_TOPIC_ARN,
                          "Credential expiration notice from {}".format(aws_account_identity),
                          report)

def myconverter(o):
    if isinstance(o, datetime):
        return o.__str__()

# get account identity info for reporting
def get_aws_account_identity():
    iam_client = boto3.client('iam')
    try:
        account_aliases = iam_client.list_account_aliases()['AccountAliases']
        if account_aliases:
            account_identity = account_aliases[0]
        else:
            logger.info("AWS account name is not set, use account id instead")
            sts_client = boto3.client('sts')
            account_identity = sts_client.get_caller_identity()['Account']
    except ClientError as e:
        logger.error(e.response['Error']['Message'])

    return account_identity

def publish_sns_topic(topic_arn, subject, message):
    client = boto3.client('sns')
    try:
        response = client.publish(TopicArn=topic_arn, Subject=subject, Message=message)
    except ClientError as e:
        logger.error(e.response['Error']['Message'])

def email_user(sender, recipient, subject, body):

        client = boto3.client('ses')

        # This address must be verified with Amazon SES.
        SENDER = sender

        # if SES is still in the sandbox, this address must be verified.
        RECIPIENT = recipient

        # Specify a configuration set. If you do not want to use a configuration
        # set, comment the following variable, and the
        # ConfigurationSetName=CONFIGURATION_SET argument below.
        # CONFIGURATION_SET = "ConfigSet"

        # If necessary, replace us-west-2 with the AWS Region you're using for Amazon SES.
        # AWS_REGION = "us-west-2"

        # The subject line for the email.
        SUBJECT_TEXT = subject

        # The email body for recipients with non-HTML email clients.
        BODY_TEXT = body

        # The HTML body of the email.
        BODY_HTML1 = """<html>
        <head></head>
        <body>
          <p>"""
        BODY_HTML2 = """</p>
        </body>
        </html>
        """

        # The character encoding for the email.
        CHARSET = "UTF-8"

        try:
            #Provide the contents of the email.
            response = client.send_email(
                Destination={
                    'ToAddresses': [
                        RECIPIENT,
                    ],
                },
                Message={
                    'Body': {
                        'Html': {
                            'Charset': CHARSET,
                            'Data': BODY_HTML1 + BODY_TEXT + BODY_HTML2,
                        },
                        'Text': {
                            'Charset': CHARSET,
                            'Data': BODY_TEXT,
                        },
                    },
                    'Subject': {
                        'Charset': CHARSET,
                        'Data': SUBJECT_TEXT,
                    },
                },
                Source=SENDER,
                # If you are not using a configuration set, comment or delete the
                # following line
                # ConfigurationSetName=CONFIGURATION_SET,
            )
        except ClientError as e:
            logger.error(e.response['Error']['Message'])
        else:
            logger.info("Email sent to " + RECIPIENT)
            logger.info("Message ID: " + response['MessageId'])


# Query the account's password policy for the password age. Return that number of days
def get_max_password_age():
    iam_client = boto3.client('iam')
    try:
        response = iam_client.get_account_password_policy()
        return response['PasswordPolicy']['MaxPasswordAge']
    except ClientError as e:
        logger.error(e.response['Error']['Message'])


# Request the credential report, download and parse the CSV
# Return a list of credentials
def get_credential_report():

    # initial request to generate report will respond with status='STARTED'
    # and may take a few seconds to 'COMPLETE'
    iam_client = boto3.client('iam')
    resp1 = iam_client.generate_credential_report()

    if resp1['State'] == 'COMPLETE':
        try:
            response = iam_client.get_credential_report()
            credential_report_csv = response['Content']
            logger.debug(credential_report_csv)
            reader = csv.DictReader(credential_report_csv.splitlines())
            credential_report = []
            for row in reader:
                credential_report.append(row)
            return(credential_report)
        except ClientError as e:
            logger.error(e.response['Error']['Message'])
    else:
        # Request again until AWS finishes generating the report
        sleep(2)
        return get_credential_report()


# Get the number of days until an access key is expired
# days <= 0 means key has expired
def get_days_until_key_expires(last_changed, max_age):
    # Ok - So last_changed can either be a string to parse or already a datetime object.
    # Handle these accordingly
    try:
        if type(last_changed) is str:
            last_changed_date=dateutil.parser.parse(last_changed).date()
        elif type(last_changed) is datetime:
            last_changed_date=last_changed.date()
        else:
            raise ValueError

        expires = (last_changed_date + timedelta(max_age)) - date.today()
    except ValueError as e:
        logger.error(e.response['Error']['Message'])

    return expires.days


def disable_key(AccessKeyId, UserName):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.update_access_key(UserName=UserName,
                                                AccessKeyId=AccessKeyId,
                                                Status='Inactive')
    except ClientError as e:
        logger.error(e.response['Error']['Message'])

if __name__ == "__main__":
    lambda_handler("event","context")
