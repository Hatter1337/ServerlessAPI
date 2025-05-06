# Powertools Lambda Layer

This layer is based on **[Powertools for AWS Lambda](https://docs.powertools.aws.dev/lambda/python/latest/)** library - a developer toolkit to implement Serverless best practices and increase developer velocity.

This Layer also includes:
- **Pydantic** for **data validation**, together with `email-validator`;
- **Environment config** a  reusable configuration object that autoloads settings from constants and Lambda environment variables, ensuring consistent configuration across services;
- **Custom exceptions** that can be reused across all services;
