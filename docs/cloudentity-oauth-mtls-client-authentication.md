# OAuth mTLS client authentication using Cloudentity

Cloudentity authorization platform provides implementation of [RFC8705 -OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705) for OAuth client authentication using mutual TLS, based on either self-signed certificates or public key infrastructure (PKI). 

Cloudentity authorization server also allows binding access tokens to the client's mutual-TLS certificate that can be used to further secure protected resource access using the access tokens.

![Cloudentity OAuth mTLS client authentication](mtls-client-auth.jpeg)
 
Let's talk a look at the high level steps required to enable OAuth mtlS support for your application with  Cloudentity authorization server.

* Register an OAuth client application in Cloudentity OAuth authorization server
  * Provide the certificate verification criteria that would be used to convey the expected subject of the certificate
  * Set the client authentication type as `self_signed_tls_client_auth` or `tls_client_auth`
* Now that the client is configured
   * Make an authorize call to get authorization code(applicable only for code grant flow)
   * Call the mtlS token endpoint in Cloudentity OAuth authorization server
      * Here the certificate presented during TLS handshake should match one of the criteria provided during registration step. If not, the authorization server will reject the access token request
* Client can use the issued access token to call protected resources.

Cloudentity exposes the required metadata in well known endpoint to showcase the supported endpoints,
authentication methods and other parameters as required in the specification.

```json
..
"token_endpoint_auth_methods_supported":[.."self_signed_tls_client_auth","tls_client_auth"..],
"tls_client_certificate_bound_access_tokens":true,
"mtls_endpoint_aliases": {
	"token_endpoint": "https://rtest.mtls.us.authz.cloudentity.io/rtest/pyron-mtls-auth-server/oauth2/token",
	"revocation_endpoint": "https://rtest.mtls.us.authz.cloudentity.io/rtest/pyron-mtls-auth-server/oauth2/revoke",
	"introspection_endpoint": "https://rtest.mtls.us.authz.cloudentity.io/rtest/pyron-mtls-auth-server/oauth2/introspect"
}, 
"mtls_issuer": "https://rtest.mtls.us.authz.cloudentity.io/rtest/pyron-mtls-auth-server",
..
```

As you can see above, Cloudentity offers dedicated endpoint for mTLS endpoints. This approach allows to have an ecosystem of mTLS protected client applications and regular client applications based on security requirements.

Below is a sample client application configuration configured for TLS Client authentication that would be matched by looking at the `Subject DN` in the handshaked certificate.

![Cloudentity OAuth mTLS client app](sample-client-mtls-dn-match.png)

### How to quickly see this in action?

Let's see this in action with some quick demonstrations

1. [Register for a free Cloudentity SaaS tenant, iff you have not already done it](https://authz.cloudentity.io/register)
   * Activate the tenant and take the self guided tour to familiarize with the platform
2. Create an OAuth client application and configure mTLS criteria
   * Choose the application type as `service`, which will configure the grant type as `client_credentials`. We are choosing this as its easy to demonstrate and skips the authorize flow. 
   * Choose the authentication type as `tls_client_auth`
   * Configure certificate metadata matching criteria from one of the below
      * subject DN
      * DNS SAN
      * ipAddress SAN
      * email SAN

> NOTE: In case you want use one of the existing cert/key pairs, use the follwing artifacts
* [client.cert](https://github.com/cloudentity/ce-samples-mtls-demo/blob/master/sample-nodejs-mtls-oauth-client/acp_cert.pem)
* [client.key](https://github.com/cloudentity/ce-samples-mtls-demo/blob/master/sample-nodejs-mtls-oauth-client/acp_key.pem)
* [ca.cert](https://github.com/cloudentity/ce-samples-mtls-demo/blob/master/sample-nodejs-mtls-oauth-client/ca.pem)

3. [Configure CA trust root certificate for TLS authentication](https://docs.authorization.cloudentity.com/guides/workspace_admin/mtls_ui/). For our example, use `ca.cert` above

4. Check the box for `Certificate bound access token` in case you need the certificate thumprint bound in the access token. If checked, this will add a new JWT Confirmation Method member `"x5t#S256"` that adheres to [RFC-8700](https://datatracker.ietf.org/doc/html/rfc7800) - Proof of Posession semantics specifictions for JSON web tokens. [`Certificate bound access token` feature can be used to increase API security, as detailed in the linked article](securing-apis-with-certificate-bound-access-token.md)   

5. Now that the client has been configured let's try to get an access Token from the authorization server using client credentials flow
  
#### Fetch access tokens 

 While mTLS is great for security, it can be quite overwhelming to use common debugging and testing techniques, but we have attached couple of ways to test this out.

 Command configuration
*  Use the RSA key pair in step 2 above in below command. Use the RSA public key in `--cert` argument & private key in `--key` argument & ca certificate in `--cacert`.
* Replace the `client_id` value with the identifier of the OAuth client client application configured in step 3
* From the registered client page in step 3, get the `TOKEN` endpoint and use it as the destination endpoint instead of `https://rtest.mtls.us.authz.cloudentity.io/rtest/pyron-mtls-auth-server/oauth2/token`

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
	"access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6I...",
	"expires_in": 3599,
	"scope": "introspect_tokens revoke_client_access revoke_tokens",
	"token_type": "bearer"
}
```

You can inspect the above access token using any jwt decoding tool, or use regular command line to decode the jwt. If you have `jq` installed use below command to decode the jwt and see the `.cnf` claim that 
has the certificate thumbprint

Command with parsed accessToken

```bash
curl  --cacert ca.crt \
      --key client.key \
      --cert client.crt \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode 'grant_type=client_credentials' \
      --data-urlencode 'client_id=c7tiikbj5qe7son8dd5g' \
      --request POST \
      -k \
      'https://rtest.mtls.us.authz.cloudentity.io/rtest/pyron-mtls-auth-server/oauth2/token' \
      | jq -r '.access_token' \
      | jq -R 'gsub("-";"+") | gsub("_";"/") | split(".") | .[1] | @base64d | fromjson'
```

Sample output

```json
{
  "aid": "pyron-mtls-auth-server",
  "amr": [],
  "aud": [
    "c8jarpgps14bttl44nf0",
    "spiffe://rtest.authz.cloudentity.io/rtest/pyron-mtls-auth-server/c7lkvhgdb74aguafli5g"
  ],
  "cnf": {
    "x5t#S256": "K-hnU2_9sOqJfUnYbhRSzc1Cpq6bDwBvN0uiwvA4c5A"
  },
  "exp": 1646789957,
  "iat": 1646786357,
  "idp": "",
  "iss": "https://rtest.authz.cloudentity.io/rtest/pyron-mtls-auth-server",
  "jti": "f45a389c-99a9-4284-b3db-b00571cd94f4",
  "nbf": 1646786357,
  "scp": [
    "introspect_tokens",
    "revoke_tokens"
  ],
  "st": "public",
  "sub": "c8jarpgps14bttl44nf0",
  "tid": "rtest"
}
```

Now you can see that the accessToken has the `cnf` claim with the `x5t#S256` certificate thumbprint.

So wrapping up, we have seen couple of things in actions
* OAuth client authenticating to an OAuth authorization server using TLS mechanism that utilizes PKI infrastructure
* Fetching a certificate bound access token for OAuth client authenticated with PKI based mutual TLS mechanism

### Further reading & examples

* [ OAuth mtLS implementation by Cloudentity overview](oauth-mtls-overview-cloudentity-platform.md)
* [Secure APIs with OAuth mTLS and certificate bound access token](securing-apis-with-certificate-bound-access-token.md)
* [Configure OAuth mTLS client authentication using self signed certificate](cloudentity-oauth-mtls-self-signed-client-authentication.md)
* [mTLS OAuth Cloudentity product guide](https://docs.authorization.cloudentity.com/features/oauth/client_auth/tls_client_auth/)

We have more sample applications built to demonstrate the OAuth mTLS capability for various use cases in various programming languages. Check out our developer articles for these here

* [Cloudentity authorization platform securing a Nodejs API using OAuth mTLS]
* [Cloudentity authorization platform securing a resource exposed via AWS API Gateway using OAuth mTLS]

Don't forget to use our [FREE tenant]((https://authz.cloudentity.io/register)). You'll find helpful [product documentation here](https://docs.authorization.cloudentity.com/) or [contact us](https://cloudentity.com/demo/) and we'd be happy to answer any questions and give you a demo.