# Local Development
This is a guide for doing local development for the Wireguard Manager.

# Prerequisites
- [Setup](SETUP.md)
- Docker

# Initial Setup
These instructions only need to be done once.  This will create the required tables in DynamoDB.

### Run DynamoDB Locally
Run the DynamoDB local docker container using the provided docker-compose.yml under the `/serverless' directory.  This will
create a local DynamoDB instance that you can use for development and testing.  

```bash
docker compose up -d dynamodb-local
```

### Deploy DynamoDB Tables

Next you will deploy the DynamoDB tables using the Serverless framework.  This will create the required tables in the 
local DynamoDB instance.

```bash
serverless dynamodb start --stage dev
```

You can check to see if the tables have been created using the AWS CLI

```bash
aws dynamodb list-tables --endpoint-url http://localhost:8000
```

# Run Wireguard Manager Locally
After that you can start the Wireguard Manger service.

```bash
docker compose up -d --build
```

You can access the API at the following address'http://localhost:5000/docs'.


For additional local development capabilities of the `serverless-dynamodb` plugin, please refer to the corresponding GitHub repository:
- https://github.com/raisenational/serverless-dynamodb
