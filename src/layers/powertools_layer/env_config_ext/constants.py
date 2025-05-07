import os

# AWS / Deployment constants
REGION = os.environ.get("REGION", "eu-west-1")
AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
PWD_SALT = "ddYIRQ7u5HeB_eHvDTG0mA=="  # TODO: Move to Secrets Manager / Parameter Store
JWT_ENCRYPTION_KEY = "ee90ec5b4254085d403fd299647a7e3a8e779cace3a20f6af91df444894a6949"  # TODO: Move to Secrets Manager / Parameter Store

# CORS constants
ALLOW_HEADERS = [
    "Content-Type",
    "Content-Language",
    "Accept",
    "Accept-Language",
    "Accept-Encoding",
    "Range",
    "Origin",
    "Cookie",
]
CORS_ORIGIN_URL = os.environ.get("CORS_ORIGIN", "'http://localhost:3000'").replace("'", "")
