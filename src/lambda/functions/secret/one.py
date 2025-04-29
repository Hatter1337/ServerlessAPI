def lambda_handler(event, context):  # noqa
    username = event.get("requestContext", {}).get("authorizer", {}).get("username", "unknown")
    return {
        "statusCode": 200,
        "body": f"Hello {username}, you accessed a protected resource!"
    }
