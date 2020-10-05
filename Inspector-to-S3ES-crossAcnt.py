import boto3 
import json
import os
import re
from elasticsearch import Elasticsearch, RequestsHttpConnection
from aws_requests_auth.aws_auth import AWSRequestsAuth

##############
# Parameters #
##############

# Environmental variables as passed during function execution
centralRegion = os.environ["AWS_REGION"]
es_host = os.environ['es_host']
es_index = os.environ['es_index']
cross_account_role = os.environ['crossAccount_role']
logging_bucket = os.environ['s3_logging_bucket']

centralAcctId = boto3.client('sts').get_caller_identity()['Account']
es_port = 443
es_doctype = 'inspector_finding'


####################
# Helper Functions #
####################

def getAWSClient(service, account, region):
    if (account == centralAcctId):
        return boto3.client(service, region_name=region)
    else:
        sts_client = boto3.client('sts')

        # Call the assume_role method of the STSConnection object and pass the role ARN and a role session name.
        # TODO: Make this code detect which IAM ARN to use (commercial or govcloud)
        assumed_role_object = sts_client.assume_role(
            RoleArn="arn:aws:iam::" + str(account) + ":role/" + cross_account_role,
            RoleSessionName="AssumeCrossAccountRoleforInspectorFindings"
        )

        # From the response that contains the assumed role, get the temporary
        # credentials that can be used to make subsequent API calls
        credentials = assumed_role_object['Credentials']
        return boto3.client(service, region_name=region,
                            aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken']
                            )

def getAWSResource(service, account, region):
    if (account == centralAcctId):
        return boto3.resource(service, region_name=region)
    else:
        sts_client = boto3.client('sts')

        # Call the assume_role method of the STSConnection object and pass the role ARN and a role session name.
        # TODO: Make this code detect which IAM ARN to use (commercial or govcloud)
        assumed_role_object = sts_client.assume_role(
            RoleArn="arn:aws:iam::" + str(account) + ":role/" + cross_account_role,
            RoleSessionName="AssumeCrossAccountRoleforInspectorFindings"
        )

        # From the response that contains the assumed role, get the temporary
        # credentials that can be used to make subsequent API calls
        credentials = assumed_role_object['Credentials']
        return boto3.resource(service, region_name=region,
                            aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken'],
                            )

##################
# Main Code #
##################

def get_custom_attributes(id, account, region):
    instance_attributes = {}
    instance_attributes['id'] = id

    # get EC2 instance attributes
    resource_ec2 = getAWSResource('ec2', account, region)
    instance = resource_ec2.Instance(instance_attributes['id'])

    instance_attributes['image_id'] = instance.image_id 
    instance_attributes['vpc_id'] = instance.vpc_id
    
    client_ec2 = getAWSClient('ec2', account, region)
    ec2_data = client_ec2.describe_instances(InstanceIds=[id])
    instance_attributes['instance_owner'] = ec2_data['Reservations'][0]['OwnerId']
    
    instance_networkifs = instance.network_interfaces_attribute

    tmp_ips = []
    tmp_subnets = []
    tmp_security_groups = []
    for interface in instance_networkifs:
        for ip in interface['PrivateIpAddresses']:
            tmp_ips.append(ip['PrivateIpAddress'])
        tmp_subnets.append(interface['SubnetId'])
        for group in interface['Groups']:
            tmp_security_groups.append(group['GroupId'])

    instance_attributes['ip_addresses'] = ", ".join(tmp_ips)
    instance_attributes['subnets'] = ", ".join(tmp_subnets)
    instance_attributes['security_groups'] = ", ".join(tmp_security_groups)
    return instance_attributes

def upload_to_es(finding, agent_id, findingRegion, findingAcct):
    auth = AWSRequestsAuth(aws_access_key=os.environ['AWS_ACCESS_KEY_ID'],
                           aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
                           aws_token=os.environ['AWS_SESSION_TOKEN'],
                           aws_host=es_host,
                           aws_region=centralRegion,
                           aws_service='es')

    es = Elasticsearch(host=es_host,
                       port=es_port,
                       use_ssl=True,
                       verify_certs=False,
                       ssl_show_warn=False,
                       connection_class=RequestsHttpConnection,
                       http_auth=auth,
                       timeout=60)

    es.index(index=es_index,doc_type=es_doctype,body=finding)
    print("Inspector Findings uploaded successfully to the Elasticsearch domain !!!")

def lambda_handler(event, context):
    s3 = getAWSClient('s3', centralAcctId, centralRegion)
    sns_message = json.loads(event['Records'][0]['body'])
    inspector_message = json.loads(sns_message['Message'])

    if inspector_message["event"] == 'FINDING_REPORTED':
        finding_arn = inspector_message['finding']
        p = re.compile("^arn:aws:inspector:([^:]+):([^:]+):(.+)$")
        findingRegion = p.match(finding_arn).group(1)
        findingAcct = p.match(finding_arn).group(2)
        findingPath = p.match(finding_arn).group(3)
    
    client_inspector = getAWSClient('inspector', findingAcct, findingRegion)
    findings_response = client_inspector.describe_findings(findingArns=[finding_arn])
    agent_id = findings_response['findings'][0]['assetAttributes']['agentId']
    
    custom_attributes = get_custom_attributes(agent_id, findingAcct, findingRegion)
    finding = findings_response['findings'][0]

    for inner_field in finding['attributes']:
        finding['attributes.' + inner_field['key']] = inner_field['value']
    
    for att_key,att_val in custom_attributes.items():
        finding['userAttributes.' + att_key] = att_val

    if 'findings' in findings_response and findings_response['findings'][0]['assetType'] == 'ec2-instance':
        try:
            s3.put_object(
                Bucket=logging_bucket,
                Body=json.dumps(finding, default=str),
                Key="AWSLogs/" + findingAcct + "/" + findingRegion + "/" + findingPath + '.json'
            )
            print("Inspector Findings uploaded successfully to the S3 bucket !!!")
        except:
            print("Inspector Findings upload to S3 bucket has FAILED !!!")
        finally:
            upload_to_es(finding, agent_id, findingRegion, findingAcct)