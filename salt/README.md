# Launch Confidant in AWS using SaltStack orchestration

This Salt orchestraton code can be used to launch a fully operational Confidant
infrastructure with an ELB, a Confidant ASG, a DynamoDB table with indexes and KMS
keys for auth and at-rest encryption.

The ASG will launch with cloud-init injected environment and installation
commands, so it's meant mostly as a getting-started configuration, rather than
what you'll eventually want to run yourself. With this configuration, updating
environment variables will require re-running the orchestration and
terminate-rolling your Confidant ASG nodes.

## Warning

This orchestration code will launch infrastructure in AWS and will incur
charges. It will use a predefined format for the naming of AWS resources:

```
service\_name-service\_instance-region
```

service\_name, service\_instance and region are user-specified through
environment variables. So, for instance, if you pass in:

```bash
SERVICE\_NAME=confidant SERVICE\_INSTANCE=production REGION=useast1
```

your resources will be named as follows:

* ELB: confidant-production-useast1
* DynamoDB table: confidant-production-useast1
* Elasticache: confidant-production-useast1
* KMS at-rest key: confidant-production-useast1
* KMS auth key: authnz-production-useast1

If you specify a DNS domain, this code will also add a route53 CNAME entry for
the ELB. For instance, if you provide example.com:

* Route53: confidant-production-useast1.example.com

## Using the orchestration code

First, you should add a _pillar/local.sls_ file, to define your environment.
See the _pillar/example.sls_ file for an example configuration with all the
options.

Next, you'll need to create a python virtualenv with the python dependencies:

```bash
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

Now you can run the orchestration:

```
env SERVICE_NAME=confidant SERVICE_INSTANCE=production REGION=useast1 salt-call -c .orchestration -m ./modules state.highstate
```
