# Serverless Framework
The serverless framework is what is used to deploy the Wireguard Manager to AWS.  It will automatically create the required
DynamoDB tables and the App Runner for the service.

These are the instructions for installing Node.js and the Serverless framework on Ubuntu.

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

sudo npm i -g serverless@4.14.3
npm install
sudo npm install serverless-dynamodb --save-dev
```

