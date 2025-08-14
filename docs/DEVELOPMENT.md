# Local Development
This is a guide for doing local development for the Wireguard Manager.

## Prerequisites
- [Setup](SETUP.md)
- Docker

## Pre-commit Hooks
Run the following to enable the pre-commit checks:
```
pip install -r requirements-dev.txt
pre-commit install
```

## Initial Service Setup
The docker commands should be run from the root project directory, and
the serverless commands should be run from the desired serverless directory.  The project currently has support for
both serverless V3 and V4, so you can choose which version you prefer.

These instructions only need to be done once.  This will create the required tables in DynamoDB.

### Run DynamoDB Locally
Run the DynamoDB local docker container using the provided docker-compose.yml under the root project directory.  This
will create a local DynamoDB instance that you can use for development and testing.

```bash
docker compose up -d dynamodb-local
```

### Deploy DynamoDB Tables

Next you will deploy the DynamoDB tables using the Serverless framework.  This will create the required tables in the
local DynamoDB instance.

```bash
serverless dynamodb start --stage local-dev
```

You can check to see if the tables have been created using the AWS CLI

```bash
aws dynamodb list-tables --endpoint-url http://localhost:8000
```

# Run Wireguard Manager Locally
The following are instructions for how to run the Wireguard manager locally in Docker or from an IDE.

## Option A: Using Docker
Run this from the root project directory.  This will start the DynamoDB server and the Wireguard Manager.

```bash
docker compose up -d --build
```

## Option B: Using an IDE
Run the following from the root project directory.
```bash
docker compose up -d dynamodb-local
```

Configure your IDE to use these parameters
```
--uvicorn-host=0.0.0.0
--uvicorn-port=5000
--environment=dev
--dynamodb-endpoint=http://0.0.0.0:8000
```

## Access the Swagger API
There is no 'front-end' interface, but there is a visual Swagger API you can use at the following address 'http://localhost:5000/docs'.
<img width="1473" height="887" alt="image" src="https://github.com/user-attachments/assets/13894bf9-eb67-4b7e-9152-874a52bac094" />
