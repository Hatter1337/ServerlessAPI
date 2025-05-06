**This folder contains AWS infrastructure resources required by the Serverless API.**

## Deploy S3 buckets 
*Required for SAM deployment.*
```bash
aws cloudformation deploy \
  --stack-name serverless-resources-s3-dev \
  --profile myapp-dev \
  --template-file src/resources/s3.yaml \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --region eu-west-1 \
  --parameter-overrides \
    ENVIRONMENT=dev
```

> **Note**: Change `myapp-dev` to your AWS CLI profile name and `eu-west-1` to your preferred region.

## Deploy DynamoDB tables
*It's recommended to deploy DynamoDB tables in a separate stack for better security and isolation.*
```bash
aws cloudformation deploy \
  --stack-name serverless-resources-dynamodb-dev \
  --profile myapp-dev \
  --template-file src/resources/dynamodb.yaml \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --region eu-west-1 \
  --parameter-overrides \
    ENVIRONMENT=dev
```
> **Note**: Change `myapp-dev` to your AWS CLI profile name and `eu-west-1` to your preferred region.

## Deploy Network infrastructure (VPC, Subnets, Security Groups)
*It's recommended to deploy network infrastructure in a separate stack so it can be reused by multiple applications.*

```bash
aws cloudformation deploy \
  --stack-name serverless-resources-network-dev \
  --profile myapp-dev \
  --template-file src/resources/network.yaml \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --region eu-west-1 \
  --parameter-overrides \
    AvailabilityZone1=eu-west-1a \
    AvailabilityZone2=eu-west-1b
```
> **Note**: Change `myapp-dev` to your AWS CLI profile name and `eu-west-1` to your preferred region.

## Deploy EC2 instance
*EC2 instance will be created in a public subnet with SSH access enabled.*

Before deploying the EC2 instance, you must create an EC2 Key Pair.
If you don't have an existing key pair, run the following command to create one:
```bash
aws ec2 create-key-pair --profile myapp-dev --region eu-west-1 --key-name myapp-key --query 'KeyMaterial' --output text > myapp-key.pem 
chmod 400 myapp-key.pem
```
This will create a new key pair named `myapp-key` and save it to a file named `myapp-key.pem`. Make sure to keep this file secure, as it will be used to SSH into the EC2 instance.

Use `myapp-key` as the value for the KeyName parameter during deployment.

```bash
aws cloudformation deploy \
  --stack-name serverless-resources-ec2-dev \
  --profile myapp-dev \
  --template-file src/resources/ec2.yaml \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --region eu-west-1 \
  --parameter-overrides \
    InstanceType=t3.micro \
    KeyName=myapp-key \
    PublicSubnetId=subnet-xxxxxxxx \
    VpcId=vpc-xxxxxxxx \
    EC2SecurityGroupId=sg-xxxxxxxx
```
> **Note**: Change `myapp-dev` to your AWS CLI profile name and `eu-west-1` to your preferred region.

## Deploy RDS PostgreSQL instance
*PostgreSQL RDS instance will be created in a public subnet with public access enabled (use only for dev/test).*

```bash
aws cloudformation deploy \
  --stack-name serverless-resources-rds-dev \
  --profile myapp-dev \
  --template-file src/resources/rds.yaml \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --region eu-west-1 \
  --parameter-overrides \
    DBInstanceIdentifier=myapp-postgres-dev \
    DBName=myappdb \
    MasterUsername=masteruser \
    MasterUserPassword=SecurePassword123 \
    VpcId=vpc-xxxxxxxx \
    PublicSubnet1Id=subnet-xxxxxxxx \
    PublicSubnet2Id=subnet-xxxxxxxx \
    RDSSecurityGroupId=sg-xxxxxxxx
```
> **Note**: Change `myapp-dev` to your AWS CLI profile name and `eu-west-1` to your preferred region.
