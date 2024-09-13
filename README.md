# Cryptomining Remediation

Ongoing work to remediate cryptomining events within JupyterLab running on a K8s cluster.

The steps include

1. A bad actor initiates a cryptomining process
2. AWS GuardDuty detects the malicious process and creates an event
3. AWS EventBridge recieves the event via CloudWatch and triggers an AWS Lambda
4. The AWS Lambda

    - Clones the root EBS volume of the EC2 that contains the Jupyter server
    - Clones the user EBS volume of the bad actor
    - Terminates the EC2
    - Emails specific admins about the event

These steps can generally be adapted for any AWS account running JupyterHub. 

Additionally for OpenScienceLab only, the bad actor is deauthorized so they cannot log in again. (Note that any current user browser cookies will need expire.)

Other JupyterHubs will have different authentication schemes. Other steps for user management will need to be customized.

AWS GuardDuty costs the most money by far. The EventBridge and AWS Lambda are pennies on the dollar. 

## Setup

To setup the codebase, do the following:

1. Setup AWS GuardDuty

2. Setup AWS EventBridge
    - Name: `no-crypto`
    - Description: `Create an event from CryptoCurrency:EC2 GuardDuty findings and trigger remediation lambda`
    - Event Pattern:
    ```json
        {
            "source": ["aws.guardduty"],
            "detail-type": ["GuardDuty Finding"],
            "detail": {
                "type": ["CryptoCurrency:EC2/BitcoinTool.B", "CryptoCurrency:EC2/BitcoinTool.B!DNS", "Execution:EC2/MaliciousFile"]
            }
        }
    ```
    - Targets: AWS Lambda function `cryptomining-remediation`

3. Setup AWS Lambda
    - Name: `cryptomining-remediation`
    - Code: Upload `./lambda_function.py`
    - Runtime: `Python 3.11`
    - Triggers: EventBridge setup in previous step
    - IAM Permissions: Add permissions found in `./iam.json`

4. (For OpenScienceLab Portal endpoint; may already exist) Setup AWS Secrets Manager SSO token

5. Adjust custom variables as needed starting Lambda code line 20:
    ```
    SNAPSHOT_FILTER_TAG = f"tag:kubernetes.io/cluster/smce-prod-cluster"  # Replace the k8s cluster name 

    TOKEN_KEY_ARN = 'Secrets Manager ARN of the SSO token secret'
    PORTAL_ENDPOINT = 'https://opensciencelab.asf.alaska.edu/portal/hub/deauthorize'  # Portal endpoint to deauthorize user 

    OSL_ADDR = 'OSL Admin email address' 
    SMCE_ADDR = 'SMCE Admin email address'

    SRC_ADDR = OSL_ADDR
    DST_ERROR_ADDR = [OSL_ADDR,]
    DST_CRYPTO_ADDR = [OSL_ADDR, SMCE_ADDR]
    ```

If adapting to a non-OpenScienceLab platform, remove Lambda code line 249 `disable_user_in_portal(email_dict.get('user_claim_name', ''))`.

## Caution
Since AWS CloudWatch defaults to updates every five minutes, it could take up to five minutes for the Lambda to run after GuardDuty determines an event. 
During this five minute interval, other GuardDuty events could be propogated.

Since multiple events per bad actor are likely to occur within a short period of time, volumes are only cloned if there have been no other pending volumes or it has been more than 15 minutes since the last succssful completion.

If an error occurs in the Lambda handler, an email is sent to the designated Admins. Please take these emails and the associated errors seriously. Otherwise, true positive events might not be handled properly. 

Even when the bad actor's EC2 is terminated, unless the user is unauthorized or disabled internally, they will be able to start up another JupyterLab server.
