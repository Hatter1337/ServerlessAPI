**TODO:** Deploy with GitHub actions workflow

Deploy S3 buckets using CloudFormation:
```
aws cloudformation deploy \
  --stack-name serverless-resources-s3-dev \
  --profile hatter \
  --template-file src/resources/s3.yaml \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --region eu-west-1 \
  --parameter-overrides \
    ENVIRONMENT=dev
```