import boto3
import datetime
import json
import logging
import traceback
import urllib3
from base64 import b64encode
from botocore.exceptions import ClientError
from escapism import unescape
from hashlib import blake2b

log = logging.getLogger()
log.setLevel(logging.INFO)

EC2 = boto3.client("ec2", region_name="us-west-2")
SES = boto3.client("ses", region_name="us-west-2")
SECRETS_MANAGER = boto3.client("secretsmanager", region_name="us-west-2")

TOKEN_KEY_ARN = "arn:aws:secretsmanager:us-west-2:381492216607:secret:sso-token/us-west-2-smce-prod-cluster-ykexlV"
PORTAL_ENDPOINT = "https://opensciencelab.asf.alaska.edu/portal/hub/deauthorize"

ROLE_ARN = "arn:aws:iam::701288258305:role/Cross-Account-Lambda-To-Cognito"
ROLE_SESSION_NAME = "CrossAccountAccess"

User_Pool_Id = "us-west-2_YA8Vab9o7"


OSL_ADDR = "uaf-jupyterhub-asf@alaska.edu"
SMCE_ADDR = "smce-security@lists.nasa.gov"

SRC_ADDR = OSL_ADDR  # should replace this functionality with hitting the send_email portal endpoint

DST_ERROR_ADDR = [OSL_ADDR, SMCE_ADDR]
DST_CRYPTO_ADDR = [OSL_ADDR, SMCE_ADDR]

DRY_RUN = False


def disable_user_in_cognito(username: str) -> None:
    # Assume Role
    sts_client = boto3.client("sts")
    response = sts_client.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName=ROLE_SESSION_NAME,
    )

    credentials = response["Credentials"]
    access_key_id = credentials["AccessKeyId"]
    secret_access_key = credentials["SecretAccessKey"]
    session_token = credentials["SessionToken"]

    assumed_role_session = boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
    )

    cognito_client = assumed_role_session.client("cognito-idp")

    # Lock User
    cognito_client.admin_disable_user(
        UserPoolId=User_Pool_Id,
        Username=username,
    )


def sign(obj, token_key) -> str:
    if type(obj) is str:
        obj = obj.encode("utf-8")
    elif type(obj) is not bytes:
        raise Exception(f"Object \"{obj}\" is not of type 'str' or 'bytes'")

    h = blake2b(digest_size=16, key=token_key)
    h.update(obj)
    return h.hexdigest()


def disable_user_in_portal(claim_name: str) -> None:
    response = SECRETS_MANAGER.get_secret_value(SecretId=TOKEN_KEY_ARN)
    token_key = response.get("SecretString").encode("utf-8")

    payload = json.dumps({"claimname": claim_name})

    sig = sign(payload, token_key)
    data: bytes = b64encode(f"{payload}:::{sig}".encode("utf-8"))

    manager = urllib3.PoolManager(num_pools=1)
    _ = manager.request(method="POST", url=PORTAL_ENDPOINT, body=data)


def get_instance(instance_id: str):
    if DRY_RUN:
        return None

    response = EC2.describe_instances(InstanceIds=[instance_id])

    instances = response["Reservations"][0]["Instances"]

    if not instances:
        raise ValueError(f"No instance found with ID: {instance_id}")

    if len(instances) > 1:
        raise ValueError(f"To many instances found with ID: {instance_id}")

    instance = instances[0]

    if instance["State"] in ["terminated", "shutting-down", "stopping", "stopped"]:
        raise ValueError(f"Instance not running found with ID: {instance_id}")

    return instance


def get_volume_ids(instance) -> list[str]:
    if DRY_RUN:
        return []

    volumes = instance["BlockDeviceMappings"]

    return [volume["Ebs"]["VolumeId"] for volume in volumes if "Ebs" in volume]


def get_modify_tags(vol_id: str, finding_id: str) -> list[dict]:
    response = EC2.describe_volumes(VolumeIds=[vol_id])
    volumes = response["Volumes"]

    vol = volumes[0]
    tags = vol.get("Tags", [])

    for d in tags:
        if d["Key"] == "Name":
            d["Value"] = f"CRYPTO_SNAPSHOT_{vol_id}_{finding_id}"

    tags.append({"Key": "do-not-delete", "Value": "True"})

    return tags


def create_snapshot(vol_id: str, tags: list[dict]) -> str:
    snapshots = EC2.describe_snapshots(
        Filters=[
            {
                "Name": "tag:kubernetes.io/cluster/smce-prod-cluster",  # Is there a better way to get the cluster name?
                "Values": ["owned"],
            },
            {"Name": "status", "Values": ["completed", "pending", "error"]},
        ],
        OwnerIds=["self"],
    )

    for snap in snapshots["Snapshots"]:
        if snap["VolumeId"] == vol_id and (
            snap["State"] == "pending"
            or (
                snap["State"] == "completed"
                and (snap["StartTime"]).replace(tzinfo=datetime.UTC)
                >= datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=15)
            )
        ):
            log.warning(f"Snapshot for volume {snap['VolumeId']} not created.")
            return snap["SnapshotId"]

    response = {}
    try:
        response = EC2.create_snapshot(
            VolumeId=vol_id,
            Description=f"snapshot of EBS volume {vol_id} in response to cryptomining",
            DryRun=DRY_RUN,
        )
    except Exception as e:
        if not e.response["Error"]["Code"] == "DryRunOperation":
            raise e
        else:
            logging.info("Dry Run snapshot creation")
            response["SnapshotId"] = "snap-04e416ea40053f32b"  # dummy snapshot,

    snapshot_id = response["SnapshotId"]

    try:
        EC2.create_tags(Resources=[snapshot_id], Tags=tags, DryRun=DRY_RUN)
    except Exception as e:
        if not e.response["Error"]["Code"] == "DryRunOperation":
            raise e
        else:
            logging.info("Dry Run tagging")

    return snapshot_id


def send_email(dest_addr: list[str], body_text: str, subject: str):
    SES.send_email(
        Destination={
            "ToAddresses": dest_addr,
        },
        Message={
            "Body": {
                "Html": {
                    "Charset": "UTF-8",
                    "Data": f"<html><body>{body_text}</body></html>",
                },
            },
            "Subject": {"Charset": "UTF-8", "Data": subject},
        },
        Source=SRC_ADDR,
    )


def send_error_email(error_msg: str, context) -> None:
    subject = "Automated email: Error handling cryptomining event"
    body_text = (
        f"An error occured during the running of the crytomining_remediation Lambda: {context.invoked_function_arn}"
        f"{error_msg}"
    )
    dest_addr = DST_ERROR_ADDR
    send_email(dest_addr, body_text, subject)


def send_crypto_alert_email(email_dict: dict) -> None:
    subject = "Automated email: A cryptomining event has been detected"
    body_text = f"""
    <p>A cryptomining event has been detected on the cluster {email_dict.get("cluster_name", "CLUSTER_NAME_UNKNOWN")}'</p>
    <ul>
    <li>GuardDuty Finding ID: {email_dict.get("finding_id", "FINDING_ID_UNKONWN")}</li>
    <li>EC2 Instance ID: {email_dict.get("instance_id", "INSTANCE_ID_UNKNOWN")}</li>
    <li>User claim name: {email_dict.get("user_claim_name", "USER_CLAIM_NAME_UNKNOWN")}</li>
    <li>Snapshot IDs: {email_dict.get("snapshot_ids", "SNAPSHOT_IDS_UNKNOWN")}</li>
    </ul>
    
    """
    if DRY_RUN:
        body_text = "<p>THIS IS A DRY RUN<p>" + body_text

    dest_addr = DST_CRYPTO_ADDR
    send_email(dest_addr, body_text, subject)


def lambda_handler(event, context):
    """
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
    """

    try:
        instance_id = event["detail"]["Resource"]["InstanceDetails"]["InstanceId"]
        finding_id = event["detail"]["Id"]

        try:
            log.info(f"Get instance object for instance id {instance_id}")
            instance = get_instance(instance_id)
        except Exception as e:
            log.error(f"{e} {traceback.format_exc()}")
            return {
                "statusCode": 200,
                "body": f"Instance {instance_id} has error '{e}'. Skipping.... arn: {json.dumps(context.invoked_function_arn)}",
            }

        log.info(f"Get volume ids for instance id {instance_id}")
        volume_ids = get_volume_ids(instance)

        email_dict = {
            "instance_id": instance_id,
            "snapshot_ids": [],
            "finding_id": finding_id,
        }

        if DRY_RUN:
            email_dict["user_claim_name"] = "claim-bbuechle"

        for vol_id in volume_ids:
            tags = get_modify_tags(vol_id, finding_id)

            for t in tags:
                if t["Key"] == "kubernetes.io/created-for/pvc/name":
                    email_dict["user_claim_name"] = t["Value"]
                if "kubernetes.io/cluster" in t["Key"]:
                    email_dict["cluster_name"] = t["Key"].split("/")[-1]

            try:
                created_snapshot_ids: str = create_snapshot(vol_id, tags)
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "SnapshotCreationPerVolumeRateExceeded"
                ):
                    log.error(f"{e} {traceback.format_exc()}")
                    return {
                        "statusCode": 200,
                        "body": f"Instance {instance_id} has error '{e}'. Skipping.... arn: {json.dumps(context.invoked_function_arn)}",
                    }
                else:
                    raise

            email_dict["snapshot_ids"].append(created_snapshot_ids)

        log.info(f"email metadata: {email_dict}")

        if DRY_RUN:
            # This is the id of the spot Dask controller
            # This will almost certainly need to be changed, as
            # EC2.terminate_instances requires an existing instance ID
            instance_id = "i-06c7d83cb761b6245"

        log.info(f"Terminating instance with id {instance_id}")
        try:
            _ = EC2.terminate_instances(InstanceIds=[instance_id], DryRun=DRY_RUN)
        except ClientError as error:
            if error.response["Error"]["Code"] == "DryRunOperation":
                log.info("Dry run instance termination successful")
            else:
                raise error

        errors = []
        log.info("Calling Portal v1 endpoint to unauthorize user...")
        try:
            disable_user_in_portal(email_dict.get("user_claim_name", ""))
        except Exception as e:
            log.info(f"Portal v1 raised an error: {e}")
            errors.append(e)

        log.info("Calling Portal v2 endpoint to unauthorize user...")
        try:
            username = unescape(email_dict.get("user_claim_name", "").lstrip("claim-"))
            disable_user_in_cognito(username)
        except Exception as e:
            log.info(f"Portal v2 raised an error: {e}")
            errors.append(e)

        if len(errors) == 2:
            raise errors[1] from errors[0]
    except Exception as e:
        log.error(
            f"Sending error email to users {DST_ERROR_ADDR}: {e}, {traceback.format_exc()}"
        )
        send_error_email(e, context)
        raise e

    log.info(f"Sending email to users: {DST_CRYPTO_ADDR}")
    send_crypto_alert_email(email_dict)

    return {"statusCode": 200, "body": json.dumps(context.invoked_function_arn)}
