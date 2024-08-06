# Environment variables for the confidant process
confidant_env:
  AWS_DEFAULT_REGION: 'us-east-1'
  AUTH_CONTEXT: '{{ grains.cluster_name }}'
  AUTH_KEY: 'authnz-{{ grains.cluster_name }}'
  AUTHOMATIC_SALT: 'H39bfLCqLbrYrFyiJIxkK0uf12rlzvgjgo9FqOnttPXIdAAuyQ'
  DYNAMODB_TABLE: '{{ grains.cluster_name }}'
  GOOGLE_OAUTH_CLIENT_ID: '123456789-abcdefghijklmnop.apps.googleusercontent.com'
  GOOGLE_OAUTH_CONSUMER_SECRET: '123456789abcdefghijklmnop'
  KMS_MASTER_KEY: '{{ grains.cluster_name }}'
  # TODO: make this point at elasticache.
  REDIS_URL: ''
  SESSION_SECRET: 'aBVmJA3zv6zWGjrYto135hkdox6mW2kOu7UaXIHK8ztJvT8w5O'
# The AWS account the resources should be placed into.
aws_account_id: '1234'
# The VPC to place these resources into.
vpc_id: 'vpc-1234'
# The availability zones the ELB and ASG should run in.
availability_zones:
  - 'us-east-1a'
  - 'us-east-1d'
  - 'us-east-1e'
# The subnets the ELB and ASG should run in. These should match the order of
# the associated availability zones.
vpc_subnets:
  # Subnet in us-east-1a
  - 'subnet-12341'
  # Subnet in us-east-1d
  - 'subnet-12342'
  # Subnet in us-east-1e
  - 'subnet-12343'
# SSH key to assign to ASG instance nodes.
ssh_boot_key_name: 'confidant-boot-key'
# An ARN of your ELB certificate.
elb_certificate: 'arn:aws:iam::1234:server-certificate/confidant-cert'
# The DNS domain name for CNAME records to attach to ELB. If this is unset,
# cnames will not be applied.
dns_domain: 'example.com'
# The profile passed to orchestration states.
orchestration_profile:
  region: 'us-east-1'

# Note that it's possible to modify these pillars based on your grain values
# (like service_name, service_instance, cluster_name, region, etc). A reason to
# do this is to be able to setup clusters in multiple regions or accounts. Here's
# an example for multi-region:
{% if grains.region == 'uswest2' %}
# vpc_id: vpc-5678
# vpc_subnets:
#  - subnet-56781
#  - subnet-56782
#  - subnet-56783
#availability_zones:
#  - 'us-west-2a'
#  - 'us-east-2b'
#  - 'us-east-2c'
#orchestration_profile:
#  region: 'us-west-2'
{% elif grains.region == 'useast1' %}
# vpc_id: vpc-1234
#availability_zones:
#  - 'us-east-1a'
#  - 'us-east-1d'
#  - 'us-east-1e'
#vpc_subnets:
#  - 'subnet-12341'
#  - 'subnet-12342'
#  - 'subnet-12343'
#orchestration_profile:
#  region: 'us-east-1'
{% endif %}
