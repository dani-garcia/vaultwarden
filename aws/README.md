# AWS Serverless Deployment Instructions

## Architecture
```
CloudFront CDN
├─ API Lambda Function
│  ├─ Data S3 Bucket
│  ├─ Aurora DSQL Database
│  └─ Amazon Simple Email Service (SES)
└─ Web-vault static assets S3 Bucket
```

## A Note On AWS Accounts and Security
It is common to have one AWS account host multiple services. But it's easy, and doesn't cost any additional amount, to separate workloads into their own accounts. Doing so makes it easier to control for security concerns and monitor costs. AWS Identity and Access Management (IAM) enforces additional controls for cross-account access than for within-account access, for example, making it harder for security attacks to hop from workload to workload when they are in separate accounts.

Given the confidential nature of data stored in Vaultwarden, it is *highly* recommended that you create a new, separate AWS account just for Vaultwarden. If you only have one account, investigate creating an [AWS Organization](https://aws.amazon.com/organizations/) to make it easy to create a second account tied to the same billing and account management mechanism, and investigate creating an [AWS IAM Identity Center](https://aws.amazon.com/iam/identity-center/) instance for easy SSO access across your accounts.

## Initial Deployment
1. Create an AWS account
1. Install the AWS CLI
1. Install AWS SAM CLI
1. Download the vaultwarden-lambda.zip Lambda Function code package (e.g. from POC GHA artifact from run https://github.com/txase/vaultwarden/actions/runs/13315966383) to this directory
1. Pick a region that supports DSQL to deploy the Vaultwarden application into (must be one of us-east-1 or us-east-2 during DSQL Preview)
1. Create an Aurora DSQL Cluster in the region using the AWS Console (this will be automated when CloudFormation ships DSQL support at GA)
1. Setup local AWS configuration to access account and region from CLI
1. Copy DSQL Cluster ID
1. Run `./deploy.sh` in this directory
    * Most parameters can be skipped at first, but you must provide the `DSQLClusterID` parameter value.
1. Note the "Output" values from the deploy command
    * These can also be retrieved later by running `sam list stack-outputs`
1. Download the latest [web-vault build](https://github.com/dani-garcia/bw_web_builds/releases) and extract it
1. Sync the web-vault build contents into the WebVaultAssetsBucket:
    * Inside the web-vault build folder run `aws s3 sync . s3://<WebVaultAssetsBucket>`, where `WebVaultAssetsBucket` is a stack output value
1. You can now navigate to your instance at the location of your `CDNDomain` stack output value

## Custom Domain
1. Create an AWS Certificate Manager (ACM) Certificate for your domain **in the us-east-1 region**
    * There are many tutorials and/or automated ways to do this, including following the official docs [here](https://docs.aws.amazon.com/acm/latest/userguide/acm-public-certificates.html)
    * It must be in the us-east-1 region because CloudFront only supports certificates from us-east-1
    * Use key algorithm RSA 2048
    * Continue to the next step once the certificate is in the *Issued* state
    * Note the certificate's ARN
1. Run `./deploy.sh` again and add the following parameter values:
    * **Domain**: `https://<custom domain>`
    * **ACMCertificateArn**: The ARN of the certificate you created for the domain
1. Create a CNAME record for the custom domain set to the value of the CDNDomain stack output

## Email via AWS Simple Email Service (SES)
Email is complicated. These instructions will not attempt to walk you through setting up SES identities for sending email. You may find docs and guides online for how to do this.

In order for Vaultwarden to send emails using SES you must have an SES Email Address Identity that **does not have a default configuration set**. An identity with a default configuration set breaks the IAM permission model set up for the Vaultwarden API Function.

Once you have an SES Identity for the sending email address, run `./deploy.sh` again and provide the email address in the `SMTP_FROM` parameter.