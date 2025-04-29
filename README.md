# ServerlessAPI
![Python 3.13](https://img.shields.io/badge/python-3.13-3776AB.svg?style=flat&logo=python&logoColor=yellow)
![SAM](https://img.shields.io/badge/SAM-v1.137.1-blue.svg)
![Powertools for AWS Lambda](https://img.shields.io/badge/Powertools%20for%20AWS%20Lambda-v3.11.0-blue.svg)

Serverless API, powered by **[AWS SAM](https://aws.amazon.com/serverless/sam/)** and **[Powertools for AWS Lambda](https://docs.powertools.aws.dev/lambda/python/latest/)**.

> **SAM** template file is located in the root directory: `template.yaml` together with configuration file `samconfig.toml`.

## Local development
### Run SAM application
- `$ sam build --profile hatter`
- `$ sam local start-api --port 8000 --profile hatter`

Instead of the `hatter` profile, use appropriate profile for the **aws cli** to access AWS resources.

#### Notes

- Ensure you have configured your **AWS CLI** with the necessary profile / credentials before running SAM commands.
- **Docker** is essential for `sam local start-api` to function, as it simulates the Lambda environment.
So, ensure **Docker** is running in the background.

### Run API using Docker Compose
**Run Docker Compose:**
- You need to grant sh script execution rights: `$ chmod +x run-local-api.sh`
- `$ docker-compose up`

#### Notes

- Ensure you have configured your **AWS CLI** with the necessary profile / credentials.
You may need to change the profile name in `run-local-api.sh` instead of the `hatter`.

## Local development - How it works

All you need to do is use the **local host**, which is 
- http://127.0.0.1:8000