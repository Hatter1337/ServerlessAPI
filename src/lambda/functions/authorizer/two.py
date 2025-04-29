def lambda_handler(event, context):  # noqa
    token = event.get("headers", {}).get("authorization")  # lowercase in HTTP API

    if token == "secret-token":
        return {
            "isAuthorized": True,
            "context": {
                "username": "example-user"
            }
        }
    else:
        return {
            "isAuthorized": False
        }
