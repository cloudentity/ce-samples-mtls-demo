# sample-go-mtls-OAuth-client

This is a sample Go OAuth client using mTLS certificates for authentication with Cloudentity’s Authorization Control Plane SaaS. Additionally, this example demonstrates 
using the Cloudentity Pyron API Gateway.

## Prerequisites

* Docker
* Golang

## To run the sample OAuth client requires two primary tasks and a third, optional, task:
1. [Prepare your Cloudentity SAAS workspace](#configure-cloudentity-saas-workspace)
2. [Run the sample OAuth client app](#build-and-run-the-go-OAuth-client-sample)

### Configure Cloudentity SAAS workspace to allow import of Workspace and Client app.
1. Sign in [Cloudentity](https://authz.cloudentity.io/)
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/signin.png?raw=true.png" width="400">]
2. Choose the System workspace workspace.
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/cswp.png?raw=true.png" width="400">]
3. Go to "Applications" in the left side bar, then choose "Clients".
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/cac.png?raw=true.png" width="400">]
4. Choose "Create Application".
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/createservice.png?raw=true.png" width="400">]
5. Create the service following the steps shown.
  * Choose "OAuth" tab.
  * Copy the Client ID and Client Secret (these will be used in step below). 
  * Scroll down and set "Token Endpoint Authentication Method" to "Client Secret Post"
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/setupservice.png?raw=true.png" width="400">]

[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/post.png?raw=true.png" width="400">]
6. Choose the "Scopes" tab and turn on `manage_configuration` in the "Management" section.
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/scopes.png?raw=true.png" width="400">]

Your workspace is now prepared to import the sample Workspace and Client. 

### Build and run the Go OAuth client sample

1. Find your tenant name and tenant URL as shown.
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/tenant.png?raw=true.png" width="400">]
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/tenant-name.png?raw=true.png" width="400">]
2. Go to the .env file in the root directory.
3. Fill in the values shown below with your configuration tenant URL, configuration tenant, client ID, and client secret.
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/env.png?raw=true.png" width="400">]
4. Run the command below in the terminal from the root of the Go sample repo.
```
make run-all
```
After successfully starting the application you will see the following console log:

```
Login endpoint available at: http://localhost:18888/login
```

4. Go to your account and verify that the MTLS OAuth Sample workspace has been imported. 
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/imported.png?raw=true.png" width="400">]
5. Go to "Governance->Policies" on the left side menu and notice that a sample policy has been created. 
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/policy.png?raw=true.png" width="400">]
6. Go to "Enforcement->APIS" on the left side menu and notice that the `/balance` endpoint is set to "Unrestricted". 
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/unrestricted.png?raw=true.png" width="400">]
7. To enforce the policy that has been created, click on "Unrestricted" for the `/balance` endpoint and set to "sample-mtls-policy". You should see that the API endpoint is now protected as shown. 
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/protected.png?raw=true.png" width="400">]
8. Now go to the URL displayed in the terminal and follow the prompts to log in. The user name for the sample Identity provider is `user` and the password is `user`.
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/login.png?raw=true.png" width="400">]
9. After logging in, note the certificate hash `x5t#S256`.
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/hash.png?raw=true.png" width="400">]
10. Finally, click the "Call Resource Server API" link to use the token to interact with the resource server. 
[<img src="https://github.com/cloudentity/ce-samples-mtls-demo/blob/incr-build/sample-go-mtls-oauth-client/img/valid.png?raw=true.png" width="400">]


Now if you enter an incorrect hash or omit the header you will fail the validation.

## Documentation

An overview of mTLS-based client Authentication can be found
[mTLS-based Client Authentication](https://docs.authorization.cloudentity.com/features/OAuth/client_auth/tls_client_auth/?q=mtls)

Authorization Control Plane extensive documentation can be found at [Cloudentity Docs](https://docs.authorization.cloudentity.com/)

Protecting API on Pyron API Gateway can be found at [Protecting API on Pyron API Gateway](https://docs.authorization.cloudentity.com/guides/developer/protect/pyron/pyron/?q=pyron)