import urllib3
import json
from hashlib import blake2b
from hmac import compare_digest
from base64 import b64decode, b64encode
import time
import datetime
import traceback
import logging
logging.setLevel(logging.INFO)
log = logging.getLogger()

import boto3
from botocore.exceptions import ClientError

EC2 = boto3.client('ec2', region_name='us-west-2')
SES = boto3.client('ses', region_name='us-west-2')
SECRETS_MANAGER = boto3.client('secretsmanager', region_name='us-west-2')

SNAPSHOT_FILTER_TAG = f"tag:kubernetes.io/cluster/smce-prod-cluster"  # Replace the k8s cluster name 

TOKEN_KEY_ARN = 'Secrets Manager ARN of the SSO token secret'
PORTAL_ENDPOINT = 'https://opensciencelab.asf.alaska.edu/portal/hub/deauthorize'  # Portal endpoint to deauthorize user 

OSL_ADDR = 'OSL Admin email address' 
SMCE_ADDR = 'SMCE Admin email address'

SRC_ADDR = OSL_ADDR
DST_ERROR_ADDR = [OSL_ADDR,]
DST_CRYPTO_ADDR = [OSL_ADDR,]# SMCE_ADDR]

def disable_user_in_portal(claim_name: str) -> None:
    response = SECRETS_MANAGER.get_secret_value(SecretId=TOKEN_KEY_ARN)
    # Note token_key might need to be encoded into bytes: .encode('utf-8')
    token_key = response.get('SecretString').encode('utf-8')
    
    def sign(obj) -> str:
        if type(obj) is str:
            obj = obj.encode('utf-8')
        elif type(obj) is not bytes:
            raise Exception(f"Object \"{obj}\" is not of type 'str' or 'bytes'")

        h = blake2b(digest_size=16, key=token_key)
        h.update(obj)
        return h.hexdigest()

    payload = json.dumps({
        "claimname": claim_name
    })

    sig = sign(payload)
    data: bytes = b64encode(f"{payload}:::{sig}".encode('utf-8'))
    
    manager = urllib3.PoolManager(num_pools=1)
    res = manager.request(method="POST", url=PORTAL_ENDPOINT, body=data)

def get_instance(instance_id: str):
    response = EC2.describe_instances(InstanceIds=[instance_id])
    instances = response['Reservations'][0]['Instances']
    
    if not instances:
        raise ValueError(f"No instance found with ID: {instance_id}")
    
    if len(instances) > 1:
        raise ValueError(f"To many instances found with ID: {instance_id}")
    
    instance = instances[0]
    
    if instance['State'] in ['terminated', 'shutting-down', 'stopping', 'stopped']:
        raise ValueError(f"Instance not running found with ID: {instance_id}")

    return instance

def get_volume_ids(instance) -> list[str]:
    volumes = instance['BlockDeviceMappings']
    
    return [volume['Ebs']['VolumeId'] for volume in volumes if 'Ebs' in volume]
    
def get_modify_tags(vol_id: str, finding_id: str) -> list[dict]:
        response = EC2.describe_volumes(VolumeIds=[vol_id])
        volumes = response['Volumes']
        
        vol = volumes[0]
        tags = vol.get('Tags', [])

        for d in tags:
            if d['Key'] == 'Name':
                d['Value'] = f'CRYPTO_SNAPSHOT_{vol_id}_{finding_id}'

        tags.append({'Key': 'do-not-delete', 'Value': 'True'})
        
        return tags
    
def create_snapshot(vol_id: str, tags: list[dict]) -> str:
    

    snapshots = EC2.describe_snapshots(
        Filters=[
            {
                "Name": SNAPSHOT_FILTER_TAG,
                "Values": ["owned"],
            },
            {"Name": "status", "Values": ["completed", "pending", "error"]},
        ],
        OwnerIds=["self"],
    )
    
    for snap in snapshots["Snapshots"]:
        if (snap["VolumeId"] == vol_id and 
           (snap["State"] == "pending" or 
           (snap["State"] == "completed" and (snap["StartTime"]).replace(tzinfo=datetime.tzinfo.utc) >= datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=15)))):
            log.warning(f'Snapshot for volume {snap["VolumeId"]} not created.')
            return snap["SnapshotId"]
    
    response = EC2.create_snapshot(
        VolumeId=vol_id,
        Description=f'snapshot of EBS volume {vol_id} in response to cryptomining',
        DryRun=False
        )
            
    snapshot_id = response['SnapshotId']
    
    EC2.create_tags(
        Resources=[snapshot_id],
        Tags = tags,
        DryRun=False
        )
        
    return snapshot_id
        
def send_email(dest_addr: list[str], body_text: str, subject: str):
    SES.send_email(
    Destination={
        'ToAddresses': dest_addr,
    },
    Message={
        'Body': {
            'Html': {
                'Charset': 'UTF-8',
                'Data': f'<html><body>{body_text}</body></html>'
            },
        },
        'Subject': {
            'Charset': 'UTF-8',
            'Data': subject                
        },
    },
    Source=SRC_ADDR
    )
        
def send_error_email(error_msg: str, context) -> None:
    subject = f'Automated email: Error handling cryptomining event'
    body_text = (
        f'An error occured during the running of the crytomining_remediation Lambda: {context.invoked_function_arn}' \
        f'{error_msg}'
        )
    dest_addr = DST_ERROR_ADDR
    send_email(dest_addr, body_text, subject)
    

def send_crypto_alert_email(email_dict: dict) -> None:
    subject = f'Automated email: A cryptomining event has been detected'
    body_text = f'''
    <p>A cryptomining event has been detected on the cluster {email_dict.get('cluster_name', 'CLUSTER_NAME_UNKNOWN')}'</p>
    <ul>
    <li>GuardDuty Finding ID: {email_dict.get('finding_id', 'FINDING_ID_UNKONWN')}</li>
    <li>EC2 Instance ID: {email_dict.get('instance_id', 'INSTANCE_ID_UNKNOWN')}</li>
    <li>User claim name: {email_dict.get('user_claim_name', 'USER_CLAIM_NAME_UNKNOWN')}</li>
    <li>Snapshot IDs: {email_dict.get('snapshot_ids', 'SNAPSHOT_IDS_UNKNOWN')}</li>
    </ul>
    
    '''
    dest_addr = DST_CRYPTO_ADDR
    send_email(dest_addr, body_text, subject)    
    

def lambda_handler(event, context):
    '''
    Upon being triggered by a CloudWatch Event tied to a GuardDuty crytomining finding,
    this lambda function:
    - snapshots the root volume associated with the user pod's EC2 instance
    - snapshots the user's volume
    - terminated the EC2 instance
    - emails a crytomining alert to admin
    
    An informational email is also sent if an error if encountered.
    
    Args:
    event: A cloudwatch event containing a GuardDuty finding related to cryptomining
    context: LambdaContext
    
    Return: Dictionary containing status code
    '''
    try:
        instance_id = event['detail']['resource']['instanceDetails']['instanceId']
        finding_id = event['detail']['id']

        try:
            log.info(f"Get instance object for instance id {instance_id}")
            instance = get_instance(instance_id)
        except Exception as e:
            log.error(f"{e} {traceback.format_exc()}")
            return {
                'statusCode': 200,
                'body': f"Instance {instance_id} has error '{e}'. Skipping.... arn: {json.dumps(context.invoked_function_arn)}"
            }
            
        log.info(f"Get volume ids for instance id {instance_id}")
        volume_ids = get_volume_ids(instance)
        
        email_dict = {
            'instance_id': instance_id,
            'snapshot_ids': [],
            'finding_id': finding_id
        }
        
        for vol_id in volume_ids:
            tags = get_modify_tags(vol_id, finding_id)
            
            for t in tags:
                if t['Key'] == 'kubernetes.io/created-for/pvc/name':
                    email_dict['user_claim_name'] = t['Value']
                if 'kubernetes.io/cluster' in t['Key']:
                    email_dict['cluster_name'] = t['Key'].split('/')[-1]
            
            try:
                created_snapshot_ids: str = create_snapshot(vol_id, tags)
            except ClientError as e:
                if e.response["Error"]["Code"] == "SnapshotCreationPerVolumeRateExceeded":
                    log.error(f"{e} {traceback.format_exc()}")
                    return {
                        'statusCode': 200,
                        'body': f"Instance {instance_id} has error '{e}'. Skipping.... arn: {json.dumps(context.invoked_function_arn)}"
                    }
                else:
                    raise
    
            email_dict['snapshot_ids'].append(created_snapshot_ids)
            
        log.info(f"email metadata: {email_dict}")    
        
        log.info(f"Terminating instance with id {instance_id}")
        response = EC2.terminate_instances(
            InstanceIds=[instance_id],
            DryRun=False
            )
        
        log.info("Calling Portal endpoint to unauthorize user...")
        disable_user_in_portal(email_dict.get('user_claim_name', ''))
            
    except Exception as e:
        log.error(f"Sending error email to users {DST_ERROR_ADDR}: {e}, {traceback.format_exc()}")
        send_error_email(e, context)
        raise e
    
    log.info(f"Sending email to users: {DST_CRYPTO_ADDR}")
    send_crypto_alert_email(email_dict)
    
    return {
        'statusCode': 200,
        'body': json.dumps(context.invoked_function_arn)
    }
