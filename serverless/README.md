# Serverless Framework and DynamoDB on AWS

This guide demonstrates how to set up local development for the wireguard-manager project using the Serverless Framework and DynamoDB.

## Prerequisites

Ensure you have Node.js and the Serverless Framework installed. You can install it globally using npm:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
NODE_MAJOR=18
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
sudo apt-get update
sudo apt-get install nodejs -y
node -v

sudo npm i -g serverless@3.38.0
npm install
```

## Local Development

### Run DynamoDB Local

Run the DynamoDB local docker container using the provided docker-compose.yml under the `/serverless' directory.  This will
create a local DynamoDB instance that you can use for development and testing.  

```bash
docker compose up -d dynamodb-local
```

### Install Serverless DynamoDB Plugin

Note: you may not need to go through the steps of installing the `serverless-dynamodb` plugin and modifying `serverless.yml`, it may be set up for you already in this repo, just do an `npm install` in this repo and jump to the Deploy DynamoDB Tables section.

```bash
sudo npm install serverless-dynamodb --save-dev
```

### Deploy DynamoDB Tables

Now you can start DynamoDB local with the following command (this will also deploy the tables):

```bash
serverless dynamodb start --stage dev
```

You can check to see if the tables have been created using the AWS CLI

```bash
aws dynamodb list-tables --endpoint-url http://localhost:8000
```

Next you will need to add your AWS Keys to the docker-compose.yml file. 

```yaml
    environment:
      - AWS_ACCESS_KEY_ID=INSERT_YOUR_ACCESS_KEY
      - AWS_SECRET_ACCESS_KEY=INSERT_YOUR_SECRET_KEY
```
After that you can start the Wireguard Manger service.

```bash
docker compose up -d --build
```

You can access the API at the following address'http://localhost:5001/docs'.

## Deploy to Staging or Production
To deploy the wireguard-manager service to staging (stg) or production (prd) to AWS, you can use the following command:

```bash
serverless deploy --stage stg
```
or
```bash
serverless deploy --stage prd
```

For additional local development capabilities of the `serverless-dynamodb` plugin, please refer to the corresponding GitHub repository:
- https://github.com/raisenational/serverless-dynamodb

