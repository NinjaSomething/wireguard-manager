## Deploy Staging/Production to AWS
This is a guide for deploying the Wireguard Manager to AWS using the Serverless framework.

Ensure Node.js and the Serverless framework are installed on your system. You can follow the instructions [here](SETUP.md).

You will need to create an AWS IAM policy and attach it to any user that will deploy the service.  The policy can be found
[here](aws_policy.json).

To deploy the wireguard-manager service to AWS, you can run the following command from
the [serverless directory](https://github.com/NinjaSomething/wireguard-manager/tree/master/serverless).  There are a
few required parameters that you will need to provide.  You can see them listed below.

```bash
serverless deploy --stage STAGE_NAME --param="vpc-id=VPC_ID" --param="pem-key-name=KEY_NAME" --param="wg-manager-version=VERSION"
```

This will use CloudFormation to create all the required resources in AWS.
* EC2 instance
* Elastic IP
* IAM Roles
* Security Groups
* DynamoDB tables

You can find the Docker image in the public repository [here](https://gallery.ecr.aws/g0d6f2g5/wireguard-manager).
