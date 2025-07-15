## Deploy Staging/Production to AWS
This is a guide for deploying the Wireguard Manager to AWS using the Serverless framework.

Ensure Node.js and the Serverless framework are installed on your system. You can follow the instructions [here](SETUP.md).

You will need to create an AWS IAM policy and attach it to any user that will deploy the service.  The policy can be found
[here](aws_policy.json).

To deploy the wireguard-manager service to staging (stg) or production (prd) to AWS, you can use the following command from 
the [serverless directory](https://github.com/NinjaSomething/wireguard-manager/tree/master/serverless):

```bash
serverless deploy --stage stg
```
or
```bash
serverless deploy --stage prd
```

This will use CloudFormation to create all the required resources in AWS.
* DynamoDB tables

## IMPORTANT NOTE
These instructions do not deploy the wireguard manager service itself.  Support for this will be added later.  You can find the 
Docker image in the public repository [here](https://gallery.ecr.aws/g0d6f2g5/wireguard-manager).
