# Serverless API
![Python 3.13](https://img.shields.io/badge/python-3.13-3776AB.svg?style=flat&logo=python&logoColor=yellow)
![SAM](https://img.shields.io/badge/SAM-v1.137.1-blue.svg)
![Powertools for AWS Lambda](https://img.shields.io/badge/Powertools%20for%20AWS%20Lambda-v3.11.0-blue.svg)

Serverless API, powered by **[AWS SAM](https://aws.amazon.com/serverless/sam/)** and **[Powertools for AWS Lambda](https://docs.powertools.aws.dev/lambda/python/latest/)**.

> **SAM** template file is located in the root directory: `template.yaml` together with configuration file `samconfig.toml`.

## 📝 Prerequisites

Before you start, make sure you have:
- **AWS account**.
- **AWS CLI** installed — [Install guide](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html).
- **AWS SAM CLI** installed — [Install guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html).

## 🔑 AWS CLI Setup

1. **Create a new IAM user** in AWS with programmatic access and attach permissions (AdministratorAccess for testing or custom policies for production).

2. **Get the Access Key ID and Secret Access Key**.

3. **Configure AWS CLI profile**:
    ```bash
    aws configure --profile myapp-dev
    ```
    Enter the following when prompted:
    ```
    AWS Access Key ID [None]: YOUR_ACCESS_KEY
    AWS Secret Access Key [None]: YOUR_SECRET_KEY
    Default region name [None]: eu-west-1 # or your preferred region
    Default output format [None]: json
    ```

> **Note**: You can choose any name instead of `myapp-dev`, but be sure to use it consistently.

## 🚀 Local development

### Start the API locally
```bash
sam build --profile myapp-dev
sam local start-api --port 8000 --profile myapp-dev
```

Your API will be available at http://localhost:8000.

## 🔧 Deployment

### First-time setup
Before deploying the application, you must provision infrastructure resources (S3 buckets, DynamoDB tables, etc.).

Follow the instructions in `src/resources/README.md` to deploy the necessary resources.
Once the resources are created, deploy the application.

### Deploy the application
After the initial setup:
```bash
sam build --profile myapp-dev
sam deploy --config-env dev --profile myapp-dev
```

## 🐞 Troubleshooting
**Q:** `An error occurred (AccessDenied) when calling the CreateChangeSet operation`

**A:** Check that your IAM user has the necessary permissions (AdministratorAccess or required CloudFormation, Lambda, S3, IAM permissions).

**Q:** `Error: Unable to locate credentials`

**A:** Make sure you ran aws configure --profile myapp-dev and are passing --profile myapp-dev in commands.