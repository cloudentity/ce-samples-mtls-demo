# OAuth mTLS client authentication & certificate bound access token with Cloudentity Authorization platform

Cloudentity authorization platform provides implementation for [RFC-8705 -OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705) - OAuth client authentication using mutual TLS, based on either self-signed certificates or public key infrastructure (PKI). 

As you might already be aware Cloudentity platform is compliant to latest emerging OAuth specifications and can support in modernizing the application architecutres with latest open standards and
specfications. These emerging specifications can be utilized to create more modern and secure application architecture and increase API and data security and reduce data breaches and exposure.

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
* secure machine to machine communication (services authentication using Dynamic Client registration)
* secure APIs from rogue clients stealing and using access tokens
* eliminate client secret as client authentication method and rely on PKI/self signed certificate - one secret less to worry about
* enable & enforce secure practices for APIs exposed to your partners/data consumers by enforcing stronger OAuth mTLS client authentication methods and binding access tokens
* add an extra layer of security with bound access tokens from dynamic workloads within a service mesh zero trust architecture

## Further reading & use cases

We have articles that will help you explore each of the topics within the specification independently to augment application development best practices. 

* [Secure APIs with OAuth Certificate Bound Access Tokens](securing-apis-with-certificate-bound-access-token.md)
* [OAuth mTLS client authentication](cloudentity-oauth-mtls-client-authentication.md)

Further more, we have developer articles to give some feel of how this could be utilzied within applications

* [Secure a NodeJS service to service communication  with Cloudentity certificate bound access token]
* [Nodejs application consuming a AWS API Gateway service protected with Cloudentity certificate bound access toekn]
* [mTLS application in Go]

### How to quickly see this in action?

You can jump right in and explore all the capabilities offered by Cloudentity

* [Register for a free Cloudentity SaaS tenant, if don't have one](https://authz.cloudentity.io/register)
   * Activate the tenant and take the self guided tour to familiarize with the platform
* Explore and try out one of the articles in above section   




