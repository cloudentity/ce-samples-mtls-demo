# Secure APIs with OAuth Certificate Bound Access Tokens

Cloudentity authorization platform completely supports the RFC8705(https://datatracker.ietf.org/doc/html/rfc8705) for OAuth Mutual-TLS Certificate-Bound Access Tokens.

With this specification support for binding the OAuth accessToken to the clients certificate, we can
* prevent the use of stolen access tokens
* replay of access tokens by unauthorized parties

Mutual-TLS certificate-bound access tokens ensure that only the party in possession of the private key corresponding to the certificate can utilize the token to access the associated resources. This constraint is
commonly referred in multiple terms like
 * key confirmation
 * proof of possession
 * holder of key
 
Let's talk a look at how Cloudentity enables support for this to secure your APIs

* Register an OAuth client application in Cloudentity OAuth authorization server
* Enable mTLS client authentication on the OAuth client application
* Enable certificate bound access token for above client to imprint certificate thumb print in tokens
* Client should call the mtlS token endpoint in Cloudentity OAuth authorization server
* Client can now call the the secure API resource with the certificate bound access token

### How to quickly see this in action?

Let's see this in action with some quick demonstrations

1. [Register for a free Cloudentity SaaS tenant, iff you have not already done it](https://authz.cloudentity.io/register)
   * Activate the tenant and take the self guided tour to familiarize with the platform
2. Create an OAuth client application and configure mTLS criteria
   * Choose the application type as `service`, which will configure the grant type as `client_credentials`. We are choosing this as its easy to demonstrate and skips the authorize flow. 
   We have provided some sample application code snippets in other articles attached below that goes through more complex flows.
   * Set the authentication type
   * Configure jwks_uri or json web key set(for self signed tls authentication)
   * Configure certificate metadata matching criteria from one of the below
      * subject DN
      * DNS SAN
      * ipAddress SAN
      * email SAN
3. Fetch an accessToken using client credentials flow
   While mTLS is great for security, it can be quite overwhelming to use common debugging and testing techniques, but we have attached couple of ways to test this out

#### Fetch access tokens 

Let's use `curl` to test this out quickly

```bash
curl  --cacert ca.crt \
      --key client.key \
      --cert client.crt \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode 'grant_type=client_credentials' \
      --data-urlencode 'client_id=c7tiikbj5qe7son8dd5g' \
      --request POST \
      -k \
      'https://rtest.mtls.us.authz.cloudentity.io/rtest/pyron-mtls-auth-server/oauth2/token' 
```

Sample output

```json
{
	"access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6IjI1ODY4OTMzNzQyMjk0NTk0NjI1MzA5NjYyMDkwOTU4NDIzOTQ0NSIsInR5cCI6IkpXVCJ9.eyJhaWQiOiJweXJvbi1tdGxzLWF1dGgtc2VydmVyIiwiYW1yIjpbXSwiYXVkIjpbImM3dGlpa2JqNXFlN3NvbjhkZDVnIiwic3BpZmZlOi8vcnRlc3QuYXV0aHouY2xvdWRlbnRpdHkuaW8vcnRlc3QvcHlyb24tbXRscy1hdXRoLXNlcnZlci9jN2xrdmhnZGI3NGFndWFmbGk1ZyJdLCJjbmYiOnsieDV0I1MyNTYiOiJjZjFSNGJ6eXFLQnN4UTdaNzFHUnlHbWtfU25mbllWSHZlQ3hhR0YzQWI4In0sImV4cCI6MTY0NjY4NjIxMiwiaWF0IjoxNjQ2NjgyNjEyLCJpZHAiOiIiLCJpc3MiOiJodHRwczovL3J0ZXN0LmF1dGh6LmNsb3VkZW50aXR5LmlvL3J0ZXN0L3B5cm9uLW10bHMtYXV0aC1zZXJ2ZXIiLCJqdGkiOiJkOGMyMzQ1NC0xOTJkLTQyMTgtYTI2ZC03NDFmYmEyNWU4ZGEiLCJuYmYiOjE2NDY2ODI2MTIsInNjcCI6WyJpbnRyb3NwZWN0X3Rva2VucyIsInJldm9rZV9jbGllbnRfYWNjZXNzIiwicmV2b2tlX3Rva2VucyJdLCJzdCI6InB1YmxpYyIsInN1YiI6ImM3dGlpa2JqNXFlN3NvbjhkZDVnIiwidGlkIjoicnRlc3QifQ.XzsDWwwuhcmlY0Y9ROCLVFEzqDUlVk8Ss8Tn_g1agT9at3dMhOn6Q86F26FFHOVv8JrPjf8RX8sAtQX-UauNSw",
	"expires_in": 3599,
	"scope": "introspect_tokens revoke_client_access revoke_tokens",
	"token_type": "bearer"
}
```

The most interesting piece is within the fetched accessToken. For example,

```json
```
Decoded view
```json
{..
  "cnf": {
    "x5t#S256": "cf1R4bzyqKBsxQ7Z71GRyGmk_SnfnYVHveCxaGF3Ab8"
  },
  ...
}
```

### Further reading & examples

[Read the Cloudentity product guide explaining more concepts and details](https://docs.authorization.cloudentity.com/features/oauth/client_auth/tls_client_auth/)

We have more sample applications built to demonstrate the mTLS capability for various use cases in
different languages. Check out our developer articles for these here

* Secured API in NodeJS protected using Cloudentity certificate bound accessToken
* AWS API Gateway resource protected using Cloudentity certificate bound accessToken

Check it out for yourself using our FREE tenant. You'll find helpful product documentation here or contact us and we'd be happy to answer any questions and give you a demo.


