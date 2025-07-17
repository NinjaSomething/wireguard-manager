# Serverless Framework
The serverless framework is used to deploy the Wireguard Manager to AWS.  It will automatically create the required
DynamoDB tables for the service.

The default is to use serverless V4, but you can use V3 by updating the package version [here](https://github.com/NinjaSomething/wireguard-manager/blob/master/package.json).

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

npm install
```
