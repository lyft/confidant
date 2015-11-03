# Fail if required environment variables aren't passed in.
{% for var in ['service_name', 'service_instance', 'region'] %}
{% if not grains.get(var, None) %}
{{ var.upper() }} environment variable check:
    test.configurable_test_state:
        - name: {{ var.upper() }} environment variable not set
        - comment: {{ var.upper() }} environment variable must be set
        - failhard: True
        - changes: False
        - result: False
{% endif %}
{% endfor %}

Ensure DynamoDB table exists:
  boto_dynamodb.present:
    - name: {{ grains.cluster_name }}
    - read_capacity_units: 10
    - write_capacity_units: 10
    - hash_key: id
    - hash_key_data_type: S
    - global_indexes:
      - data_type_date_index:
        - name: "data_type_date_index"
        - read_capacity_units: 10
        - write_capacity_units: 10
        - hash_key: data_type
        - hash_key_data_type: S
        - range_key: modified_date
        - range_key_data_type: S
      # TODO: get rid of this index
      - data_type_revision_index:
        - name: "data_type_revision_index"
        - read_capacity_units: 10
        - write_capacity_units: 10
        - hash_key: data_type
        - hash_key_data_type: S
        - range_key: revision
        - range_key_data_type: N
    - profile: orchestration_profile

Ensure {{ grains.cluster_name }} security group exists:
  boto_secgroup.present:
    - name: {{ grains.cluster_name }}
    - description: {{ grains.cluster_name }}
    - vpc_id: {{ pillar.vpc_id }}
    - rules:
        # TLS terminated traffic from the ELB
        - ip_protocol: tcp
          from_port: 80
          to_port: 80
          source_group_name:
            - {{ grains.cluster_name }}
        # Access to elasticache
        - ip_protocol: tcp
          from_port: 6379
          to_port: 6379
          source_group_name:
            - {{ grains.cluster_name }}
    - profile: orchestration_profile

Ensure {{ grains.cluster_name }} iam role exists:
  boto_iam_role.present:
    - name: {{ grains.cluster_name }}
    - policies:
        'iam':
          Version: '2012-10-17'
          Statement:
            - Action:
                - 'iam:ListRoles'
                - 'iam:GetRole'
              Effect: 'Allow'
              Resource: '*'
        'kms':
          Version: '2012-10-17'
          Statement:
            - Action:
                - 'kms:GenerateRandom'
              Effect: 'Allow'
              Resource: '*'
        'dynamodb':
          Version: '2012-10-17'
          Statement:
            - Action:
                - 'dynamodb:*'
              Effect: 'Allow'
              Resource:
                - 'arn:aws:dynamodb:*:*:table/{{ grains.cluster_name }}'
                - 'arn:aws:dynamodb:*:*:table/{{ grains.cluster_name }}/*'
            - Action:
                - 'dynamodb:DeleteTable'
              Effect: 'Deny'
              Resource:
                - 'arn:aws:dynamodb:*:*:table/{{ grains.cluster_name }}'
    - profile: orchestration_profile

Ensure {{ grains.cluster_name }} elb exists:
  boto_elb.present:
    - name: {{ grains.cluster_name }}
    - subnets: {{ pillar.vpc_subnets }}
    - scheme: internal
    - security_groups:
        - {{ grains.cluster_name }}
    - listeners:
        - elb_port: 443
          instance_port: 80
          elb_protocol: HTTPS
          instance_protocol: HTTP
          certificate: '{{ pillar.elb_certificate }}'
        - elb_port: 80
          instance_port: 80
          elb_protocol: HTTP
          instance_protocol: HTTP
    - health_check:
        target: 'HTTP:80/healthcheck'
        timeout: 4
        interval: 5
        healthy_threshold: 3
        unhealthy_threshold: 8
    {% if pillar.get('dns_domain', '') %}
    - cnames:
        - name: {{ grains.cluster_name }}.{{ pillar.dns_domain }}
          zone: {{ pillar.dns_domain }}
    {% endif %}
    - profile: orchestration_profile

Ensure cache-subnet-{{ pillar.availability_zones[0] }} elasticache subnet group exists:
  boto_elasticache.subnet_group_present:
    - name: cache-subnet-{{ pillar.availability_zones[0] }}
    - subnet_ids: {{ pillar.vpc_subnets[0] }}
    - description: {{ pillar.vpc_subnets[0] }} cache subnet
    - profile: orchestration_profile

Ensure {{ grains.cluster_name }} elasticache exists:
  boto_elasticache.present:
    - name: {{ grains.cluster_name }}
    - engine: redis
    - cache_node_type: cache.t1.micro
    - num_cache_nodes: 1
    - security_group_ids:
      - {{ grains.cluster_name }}
    - preferred_availability_zone: {{ pillar.availability_zones[0] }}
    - cache_subnet_group_name: cache-subnet-{{ pillar.availability_zones[0] }}
    - profile: orchestration_profile

Ensure {{ grains.cluster_name }} asg exists:
  boto_asg.present:
    - name: {{ grains.cluster_name }}
    - launch_config_name: {{ grains.cluster_name }}
    - launch_config:
      # TODO: load this from pillars. This specific AMI is us-east-1, ubuntu
      # trusty, hvm-ssd
      - image_id: ami-ff02509a
      - key_name: {{ pillar.ssh_boot_key_name }}
      - security_groups:
        - {{ grains.cluster_name }}
      - instance_profile_name: {{ grains.cluster_name }}
      # TODO: load this from pillars
      - instance_type: t2.medium
      - associate_public_ip_address: True
      - instance_monitoring: true
      - cloud_init:
          scripts:
            salt: |
              #!/bin/bash
    - vpc_zone_identifier: {{ pillar.vpc_subnets }}
    - availability_zones: {{ pillar.availability_zones }}
    - min_size: {{ pillar.availability_zones|length }}
    - max_size: {{ pillar.availability_zones|length * 2}}
    - tags:
      - key: 'Name'
        value: '{{ grains.cluster_name }}'
        propagate_at_launch: true
    - profile: orchestration_profile

Ensure {{ grains.cluster_name }} key is managed:
  boto_kms.key_present:
    - name: {{ grains.cluster_name }}
    - policy:
        Id: key-policy-1
        Statement:
          - Action: 'kms:*'
            Effect: Allow
            Principal:
              AWS: 'arn:aws:iam::{{ pillar.account_id }}:root'
            Resource: '*'
            Sid: Enable IAM User Permissions
          - Action:
              - kms:DescribeKey
              - kms:GenerateDataKey*
              - kms:Encrypt
              - kms:ReEncrypt*
              - kms:Decrypt
            Effect: Allow
            Principal:
              AWS: 'arn:aws:iam::{{ pillar.account_id }}:role/{{ grains.cluster_name }}'
            Resource: '*'
            Sid: Allow use of the key
        Version: '2012-10-17'
    - description: '{{ grains.cluster_name }} data at rest key'
    - key_rotation: True
    - enabled: True
    - profile: orchestration_profile

Ensure authnz-{{ grains.cluster_name }} key is managed:
  boto_kms.key_present:
    - name: authnz-{{ grains.cluster_name }}
    - policy:
        Id: key-policy-1
        Statement:
          - Action: 'kms:*'
            Effect: Allow
            Principal:
              AWS: 'arn:aws:iam::{{ pillar.account_id }}:root'
            Resource: '*'
            Sid: Enable IAM User Permissions
          - Action:
              - kms:DescribeKey
              - kms:GenerateDataKey*
              - kms:Encrypt
              - kms:ReEncrypt*
              - kms:Decrypt
            Effect: Allow
            Principal:
              # Allow all regions to decrypt/encrypt using this key.
              AWS: 'arn:aws:iam::{{ pillar.account_id }}:role/{{ grains.cluster_name }}'
            Resource: '*'
            Sid: Allow use of the key
          - Action:
              - kms:ListGrants
              - kms:CreateGrant
              - kms:RevokeGrant
            Effect: Allow
            Principal:
              # Only allow this specific region to manage grants for this key.
              AWS: 'arn:aws:iam::{{ pillar.account_id }}:role/{{ grains.cluster_name }}'
            Resource: '*'
            Sid: Allow attachment of persistent resources
        Version: '2012-10-17'
    - description: 'authnz-{{ grains.cluster_name }} key'
    - key_rotation: True
    - enabled: True
    - profile: orchestration_profile
