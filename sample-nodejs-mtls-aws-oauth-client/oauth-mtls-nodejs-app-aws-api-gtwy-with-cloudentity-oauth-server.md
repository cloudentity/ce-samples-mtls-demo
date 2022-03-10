# Configuring a Node.js Application using mTLS with Cloudentity Amazon API Gateway Authorizer & AWS API Gateway

In a [previous article](link to previous article), we created a Node.js application to use Mutual-TLS and certificate bound access tokens with [Cloudentity Authorization Platform](https://authz.cloudentity.io/). In this tutorial, we will configure the application to use the [Cloudentity Amazon API Gateway Authorizer](https://docs.authorization.cloudentity.com/guides/developer/protect/aws_api_gw/aws/?q=aws%20api) to enforce an API access policy. 

The authorization server will issue certificate bound access tokens to the Node.js client application and the client application will then access a protected resource via AWS API Gateway. AWS API Gateway will use Cloudentity AWS API Gateway authorizer to enforce the certificate hash in the JWT matches the hash of the certificate taken from its TLS layer as per a policy which we will create. 

### Prerequisites

##### Cloudentity SaaS
Cloudentity offers a free SaaS Tenant and you can sign up for one, if you have not already, for a free account. With this you are basically getting a free OAuth/OIDC compliant server with all the latest specifications comprising of OpenData initiatives across the world.

##### Go Application
- [Node.js](https://nodejs.org) - Recommended v16.x +
- [AWS Account with priviledges to Create Lambda functions and AWS API Gateway](https://aws.amazon.com/)

### Basic Concepts - TODO Update to use new concepts intro
OAuth 2.0 Mutual-TLS client authentication and certificate bound access tokens is explained in [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705). When following a traditional OAuth 2.0 authorization code flow, the access token is all that is required to access a protected resource. However, anyone with access to this token can then access the resource even if the token should not be in their possession. Mutual-TLS client authentication allows us to bind access tokens to a client’s x.509 certificate and this allows the resource server to verify that the presenter of this access token was issued this token.  

Once the client receives a certificate bound access token it will send the token in the authorization header when calling the resource server API. The token includes the `cnf` claim which has the `x5t#S256` confirmation method member.  The value of this member is the base64url-encoded SHA-256 hash, or thumbprint of the DER encoding of the x.509 certificate. Since we are using AWS API Gateway for our protected resource API, AWS API Gateway will terminate the TLS connection and then inject the X.509 certificate into the Cloudentity lambda authorizer. The authorizer will then enforce our policy by taking the hash of the certificate and comparing it to the `cnf` claim in the token. If they match then access to the protected resource is authorized, otherwise the request is not authorized.

### Prepare Cloudentity SaaS
We need a client application and workspace configured in [Cloudentity Authorization Platform](https://authz.cloudentity.io/).

First, add your trusted client certificates to your workspace as shown in [Configuring Cloudentity Authorization Platform to verify the client mTLS authentication](https://docs.authorization.cloudentity.com/guides/workspace_admin/mtls_ui/?q=mtls).

Next, create a client application as shown and configure it to use mTLS shown in [mTLS Enabled Application](https://docs.authorization.cloudentity.com/guides/developer/mtls/#create-application).

Additional information on using mTLS with Cloudentity Authorization Platform see [mTLS OAuth client authentication in a nutshell](https://docs.authorization.cloudentity.com/features/oauth/client_auth/tls_client_auth/?q=mtls).

## Preparing AWS API Gateway
We need to prepare AWS API Gateway and AWS Lambda to use the Cloudentity Amazon API Gateway authorizer. 

Follow this detailed guide to setup AWS for your Cloudentity authorizer - [Protecting APIs deployed behind the AWS API Gateway](https://docs.authorization.cloudentity.com/guides/developer/protect/aws_api_gw/aws/).

### Configure AWS API Gateway to use custom domain and mTLS.

Log in to your [AWS acount](https://aws.amazon.com/) and go to the API that you created in the previous step. 

 Mutual-TLS requires a custom domain. On the left side choose 'Custom Domain Names'. 
 ![select custom domain](images/custom-select.png)
 
 Select your domain or [create a new one](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-custom-domains.html) if necessary. Once you have selected your custom domain, under 'Domain Details' choose 'Edit'. 
 ![edit domain details](images/custom-edit1.png)
 
 Select 'Mutual TLS authentication' and enter your trust store URI. The trust store URI will be a location where AWS can retrieve the contents of your trusted certificate. If you have a link to your trust store URI then use that. Otherwise, you can upload the your pem encoded trusted certificate that you are using to S3 and use that URI. Click 'Save'. Once you save you will see the Domain Details pane and 'Mutual TLS' will turn green showing that mTLS is now active. 
 ![setting trust store](images/trust-store.png)
 
 Inside 'Configuration' choose 'Edit' under 'Endpoint Configuration'. 
 ![edit configuration](images/edit-config.png)
 
 Select your ACM certificate and save.
 ![set acm](images/acm.png)

 Click the 'API Mappings' tab choose 'Configure API Mappings' and select the API and stage that you created in AWS API Gateway then save.
![configure mappings](images/config-mappings.png)

 Go back to your API and on the left menu choose 'Settings'. Under 'Default Endpoint' choose 'Disabled'. This ensures that only your custom domain is called instead of the default URL that was created automatically when you created the API.
  ![disable default](images/disable-default.png)
  
Your AWS API Gateway is now using Mutual-TLS and the Cloudentity Amazon API Gateway Authorizer to protect your API. 

### Running the Node.js Application

Let's run the application without a policy set for the authorizer to enforce. We will add the policy in the next section.

At the root of the project go to the `.env` file and enter the following:
- MTLS_OAUTH_CLIENT_ID
- MTLS_OAUTH_CLIENT_SECRET
- MTLS_OAUTH_TOKEN_URL
- MTLS_RESOURCE_URL 

Your `MTLS_RESOURCE_URL` is the url of the resource we created in AWS API Gateway. It will be your custom domain plus the API path. For example, if you created the example API and your custom domain is `api.example.com` then your MTLS_RESOURCE_URL would be `https://api.example.com/pets`.

Now run the application from terminal at the root of the project with 
```
npm start
```

Now go to `http://localhost:5002/home` and get an access token by clicking 'Get Certificate Bound Access Token'.  Notice the `cnf` claim with the x5t#S256 member. This is the certificate thumbprint. Now click 'Call Resource server with Certificate Bound Access Token' and verify that you receive a JSON response. In the case of the `/pets/` API it will be a JSON response of pets. 

### Creating and enforcing a policy

Currently, a policy is not set on the API in Cloudentity Authorization Platform. Go back to your tenant in [Cloudentity Authorization Platform](https://authz.cloudentity.io/) and go to Enforcement-APIs. Since we chose 'Create and bind services automatically' our APIs appear here automatically. 
![api enforcement](images/enforcement.png)

We will quickly walk through setting up a a policy but for a more detailed explanation of using the policy editor see [Creating Policy](https://docs.authorization.cloudentity.com/guides/developer/protect/access_control/create_auth_policy/?q=policy). 

Select the API you wish to protect with a policy. For the example API we choose `GET /pets`. Notice the API shows 'Unrestricted'. Click 'Unrestricted' and choose 'Add new policy'. Give the policy a name and choose 'Cloudentity' for the policy language. Click 'Create'. 
![name policy](images/name-policy.png)

Save the following policy to a file.
```
validators:
  - name: attributes
    conf:
      fields:
        - comparator: equals
          field: 'request.mtls.x5t#S256'
          value: '$authnCtx.cnf.x5t#S256'
    recovery: null
```

Click on the trash can to delete the existing 'Fail' policy. Now in the policy editor click the 3 dots in the top right of the editor and select 'Upload'.  
![upload policy](images/upload-policy.png)

Upload the policy you just saved to a file. After uploading click 'Save'.
![save policy](images/save-policy.png)

The policy enforces the request context includes the certificate thumbprint of the X.509 certificate that was injected by AWS API Gateway into our authorizer. It verifies that this thumbprint is equal to the certficate thumbprint that is inluded in the access token, that is the certificate bound to the access token is equal to the certificate that was used during the mTLS handshake. If they are equal then the authorizer allows access to the resource. If they are not equal then the authorizer will reject access to the resource.

Once you save the policy press the back arrow and save the policy on the API you wish to protect. You should see your API is now protected with your new policy.
![protected by policy](images/protected-policy.png)

Now in your browser go back to `http://localhost:5002/home` and verify that you can still access the protected resource after obtaining an access token.

You can also look in CloudWatch logs to see the status of a request. In your lambda function go to 'Monitor' and then click 'View logs in CloudWatch'. You will see the logs for this lamdba function. Make a request and notice that the logs will show that the policy was checked during the request and that the request was authorized or denied. For example, the following shows the resource requested was `/pets`. The policy name is shown, here it is `mtls-aws-api-gateway-mtls-policy` as that is the name we gave the policy. We see the status is `AUTHORIZED`.
```
{
…
    "msg": "request validated",
    "path": "/pets",
    "rule": {
        "method": "GET",
        "path": "/pets",
        "policyName": "mtls-aws-api-gateway-mtls-policy",
        "API": {
            "api_type": "rest",
            "can_have_policy": true,
            "method": "GET",
            "path": "/pets",
            "policy_id": "mtls-aws-api-gateway-mtls-policy", 
        }
    },
    "stage": "dev",
    "status": "AUTHORIZED",
}
```

### Conclusion
[Cloudentity Authorization Platform](https://authz.cloudentity.io/) fully supports Mutual-TLS authentication and certificate bound access tokens. Using the Cloudentity Amazon API Gateway authorizer, we were able to specify a policy that enforces that the access token is bound with the certificate used during the TLS handlshake. We created an authorizer and uploaded it to AWS Lambda. We also configured AWS API Gateway to use the Cloudentity authorizer. 

### Relevant Links
 - [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
 - [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)
 - [Mutual-TLS with AWS API Gateway](https://aws.amazon.com/blogs/compute/introducing-mutual-tls-authentication-for-amazon-api-gateway/)
 - [Custom Domains with AWS API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-custom-domains.html)

