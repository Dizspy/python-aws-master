import boto3
import socket
import datetime
import sys, os, base64, datetime, hashlib, hmac
import requests # pip install requests
import xmltodict # pip install xmltodict

FQDNs = ['a.itsm.org.ua', 'b.itsm.org.ua', 'c.itsm.org.ua']

PUBLIC_IPS = [socket.gethostbyname(e) for e in FQDNs]
MAX_AGE = 7

ec2 = boto3.resource('ec2')
stopped_instances = []

def __get_instances_by_http( public_ips):
    credential = boto3.session.Session().get_credentials();
    access_key = credential.access_key
    secret_key = credential.secret_key
    
    filters_values = '&'.join(['Filter.1.Value.{0}={1}'.format(idx + 1, ip) for idx, ip in enumerate(public_ips)])
    method = 'GET'
    service = 'ec2'
    host = 'ec2.eu-west-1.amazonaws.com'
    region = 'eu-west-1'
    endpoint = 'https://ec2.eu-west-1.amazonaws.com'
    request_parameters = 'Action=DescribeInstances&Filter.1.Name=network-interface.addresses.association.public-ip&{0}&Version=2016-11-15'.format(filters_values)

    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def getSignatureKey(key, dateStamp, regionName, serviceName):
        kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
        kRegion = sign(kDate, regionName)
        kService = sign(kRegion, serviceName)
        kSigning = sign(kService, 'aws4_request')
        return kSigning

    if access_key is None or secret_key is None:
        print 'No access key is available.'
        sys.exit()

    t = datetime.datetime.utcnow()
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')

    canonical_uri = '/' 
    canonical_querystring = request_parameters
    canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
    signed_headers = 'host;x-amz-date'
    payload_hash = hashlib.sha256('').hexdigest()

    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()
    signing_key = getSignatureKey(secret_key, datestamp, region, service)
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
    headers = {'x-amz-date':amzdate, 'Authorization':authorization_header}
    request_url = endpoint + '?' + canonical_querystring

    r = requests.get(request_url, headers=headers)

    xml = r.text
    doc = xmltodict.parse(xml)
    reservations = doc['DescribeInstancesResponse']['reservationSet']
    rows = []
    for r in reservations:
        reservation = reservations[r]
        instances = reservation['instancesSet']        
        for key in instances:
            instance = instances[key]
            public_ip = instance['ipAddress']
            rows.append([
                FQDNs[public_ips.index(public_ip)],
                instance['tagSet']['item']['value'] if 'tagSet' in instance else '',
                instance['instanceId'],
                instance['instanceType'],
                public_ip,
                instance['privateIpAddress'] if 'privateIpAddress' in instance else '',
                instance['keyName'],
                instance['instanceState']['name'],
                instance['monitoring']['state']
            ])
    return rows
    

def _spacer(value, columnLength):
    return (value + ' ' * columnLength)[:columnLength]

def _get_headers():
    return  [
        'Name',
        'Instance ID',
        'Instance Type',
        'IPv4 Public IP',
        'IPv4 Private IP',
        'Key Name',
        'Instance State',
        'Monitoring'
    ]

def _get_instance_values(instance):
    return [
        instance.tags[0]['Value'] if instance.tags else '',
        instance.id,
        instance.instance_type,
        instance.public_ip_address if instance.public_ip_address else '',
        instance.private_ip_address if instance.private_ip_address else '',
        instance.key_name,
        instance.state['Name'],
        instance.monitoring['State']
    ]

def _print_headers(headers, columnLength):
    line = ' | '.join([_spacer(h, columnLength) for h in headers])
    print line

    line = ' | '.join(['-' * columnLength for h in headers])
    print line

def _print_row(values, columnLength):
    line = ' | '.join([_spacer(v, columnLength) for v in values])
    print line

headers = _get_headers()

print 'Determining instances states ...'
print('\n')

print 'Using HTTP Verification'
_print_headers(['FQDN'] + headers, 18)
instances = __get_instances_by_http(PUBLIC_IPS)
for values in instances:
    _print_row(values, 18)


print 'Using TCP Verification'
_print_headers(['FQDN'] + headers, 18)

for instance in ec2.instances.filter(
        Filters=[{
            'Name': 'network-interface.addresses.association.public-ip',
            'Values': PUBLIC_IPS
        }]):
    state = instance.state['Name']
    fqdn = FQDNs[PUBLIC_IPS.index(instance.public_ip_address)]
    instance.fqdn = fqdn
    _print_row([instance.fqdn] + _get_instance_values(instance), 18)

    if state == 'stopped':
        stopped_instances.append(instance)

print 'Creating AMI for stopped instances ...'
for si in stopped_instances:
    name = si.tags[0]['Value'] + datetime.datetime.now().strftime('%Y-%m-%d %H-%M-%S')
    description = si.tags[0]['Value'] + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    image = ec2.meta.client.create_image( Description=description, InstanceId=si.id, Name=name)
    tags = ec2.meta.client.create_tags(
        Resources = [image['ImageId']],
        Tags = [
            {
                'Key': 'Name',
                'Value': description,
            },
        ],
    )

    # print 'Terminating stopped EC2 instance:', si.id, '...'
    # response = ec2.meta.client.terminate_instances(
    #     InstanceIds=[
    #         si.id
    #     ]
    # )

    print 'Clean up AMIs older than 7 days ...'
    response = ec2.meta.client.describe_images(
        Owners=[
            'self',
        ]
    )
    for image in response['Images']:
        created_on = datetime.datetime.strptime(image['CreationDate'][:-5], '%Y-%m-%dT%H:%M:%S')
        age = (datetime.datetime.today() - created_on).days
        if age > MAX_AGE:
            response = ec2.meta.client.deregister_image(
                ImageId=image['ImageId']
            )

print('\n')
print 'Print all EC2 instances ...'
print('\n')
_print_headers(headers, 18)
for instance in ec2.instances.all():
    _print_row(_get_instance_values(instance), 18)
