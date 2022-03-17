# OAuth mTLS client authentication & certificate bound access token with Cloudentity Authorization platform

Cloudentity authorization platform provides implementation for [RFC-8705 -OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705) - OAuth client authentication using mutual TLS, based on either self-signed certificates or public key infrastructure (PKI). 

As you might already be aware Cloudentity platform is compliant to the latest emerging OAuth specifications and can support in modernizing the application architecutres with the latest open standards and
specifications. These emerging specifications can be utilized to create more modern and secure application architectures and increase API and data security and reduce data breaches and exposure.

## Main features

Cloudentity authorization server supports all the specification aspects that includes highlights such as
* tls signed client authentication
* self signed tls client authentication
* certificate bound access token
* tls certificate match on various SAN including email, uri, ipaddress, name etc
* issue binding/non-binding access tokens
* introspection/revocation endpoints 
* enforce mtls setting at global level/client level

![Cloudentity mtls](mtls-rfc-8705.jpeg)

## Usage

[RFC8705 -OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705) can be used to modernize the way applications interact with each other and to increase security posture of the applications running in your infrastructure.
* secure machine to machine communication - service registration using DCR( Dynamic Client Registration) and then authenticating using mTLS
* secure APIs from rogue clients using stolen access tokens
* eliminate client secret as client authentication method and rely on PKI/self signed certificate - one secret less to worry about
* enable & enforce secure practices for APIs exposed to your partners/data consumers by enforcing stronger OAuth mTLS client authentication methods and binding access tokens
* add an extra layer of security with bound access tokens from dynamic workloads within a service mesh zero trust architecture

### Further reading & examples

* [ Securing partner API integrations with OAuth mTLS](oauth-mtls-partner-api-ecosystem-protection.md)
* [ OAuth mtLS implementation by Cloudentity overview](oauth-mtls-overview-cloudentity-platform.md)
* [Configure OAuth mTLS client authentication using TLS](cloudentity-oauth-mtls-client-authentication.md)
* [Configure OAuth mTLS client authentication using self signed certificate](cloudentity-oauth-mtls-self-signed-client-authentication.md)
* [Secure APIs with OAuth mTLS and certificate bound access token](securing-apis-with-certificate-bound-access-token.md)

* [mTLS OAuth concept](https://docs.authorization.cloudentity.com/features/oauth/client_auth/tls_client_auth/)

Further more, We have built some reference applications to demonstrate the OAuth mTLS capability for various use cases in various programming languages, to provide and idea of how this could be utilized within your applications. Check out our developer articles for these here

* [Cloudentity authorization platform securing a Nodejs API using OAuth mTLS]
* [Cloudentity authorization platform securing a resource exposed via AWS API Gateway using OAuth mTLS]
* [mTLS client authentication and fetch certificate bound access token using OAuth PKCE flow in a Go application from Cloudentity authorization platform]

### How to quickly see this in action?

You can jump right in and explore all the capabilities offered by Cloudentity

* [Register for a free Cloudentity SaaS tenant, if don't have one](https://authz.cloudentity.io/register)
   * Activate the tenant and take the self guided tour to familiarize yourself with the platform
* Explore and try out one of the articles in the `Further reading & examples` section above
* In case you want to explore more Cloudentity features, check out [Cloudentity product documentation here](https://docs.authorization.cloudentity.com/) or [contact us](https://cloudentity.com/demo/) and we'd be happy to answer any questions and give you a demo.




