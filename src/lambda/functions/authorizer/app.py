def lambda_handler(event, context):  # noqa
    token = event.get("headers", {}).get("Authorization")

    if token == "secret-token":
        return {
            "principalId": "user123",  # required field
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": "Allow",
                        "Resource": event["methodArn"]
                    }
                ]
            },
            "context": {
                "username": "demo-user"
            }
        }
    else:
        return {
            "principalId": "anonymous",
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": "Deny",
                        "Resource": event["methodArn"]
                    }
                ]
            }
        }
