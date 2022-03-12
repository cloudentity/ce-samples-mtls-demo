# Node.js app using OAuth mTLS with Cloudentity Authorization platform

Cloudentity authorization platform completely supports [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) for OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens.
As you might already be aware Cloudentity platform is compliant to latest emerging OAuth specifications and can support in modernizing the application architecutres with latest open standards and
specfications support. We will take you down the path of understanding use cases that can be addressed using mTLS specification, code samples in various language on how to integrate and utilize the latest
specification in your new architecture patterns.

In this specific section , we will be creating a Nodejs application and calling a resource server protecting a resource with mTLS bound accessToken
This article is geared towards showing a backend application calling another service

## Pre-requisites

* Cloudentity Authorization Platform tenant - 
  Cloudentity offers a free SaaS Tenant and [you can sign up for one, if you have not already got one](https://authz.cloudentity.io/register). With this you will get a free OAuth/OIDC compliant server with all the latest specifications.

* Application builder tools - We will build and run the application locally
	* [Node.js](https://nodejs.org)  - Recommended v16.x+
	* [npm](https://www.npmjs.com)

### Basic Concepts
OAuth 2.0 Mutual-TLS client authentication and certificate bound access tokens is explained in [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705). We have simplified it for you in case you want to understand usage scenarios with some simple examples
* [OAuth mtLS implementation by Cloudentity overview](oauth-mtls-overview-cloudentity-platform.md)
* [Configure OAuth mTLS client authentication using self signed certificate](cloudentity-oauth-mtls-self-signed-client-authentication.md)
* [Configure OAuth mTLS client authentication using TLS](cloudentity-oauth-mtls-client-authentication.md)
* [Secure APIs with OAuth mTLS and certificate bound access token](securing-apis-with-certificate-bound-access-token.md)

Let's look at an overview of how mTLS works to help secure your application from rogue callers that have obtained an access token.
![mtls overview](https://github.com/cloudentity/ce-samples-mtls-demo/blob/nodejs-mtls/docs/cloudentity-api-risk-mitigation-mtls.jpeg).

When not using mTLS the client is issued an access token. Unfortunately, a rogue application has also obtained this access token. When not using mTLS, anyone in possession of the access token is able to access a protected resource using that access token. 

Fortunately, we have a way to prevent a rogue caller from using a stolen access token. We can use Mutual-TLS as described in [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705). The client is issue an access token. A rogue caller gets access to the access token. However, since we are using mTLS we have a certificate bound access token. Since the rogue caller does not have access to our certificate, the rogue caller attempts to use the access token and the protected resource denies access to the resource since the certificate does not match the certificate thumbprint bound to the access token.

### Source repo

We expect Javscript programming language experience to understand the programming constructs, in case you want to just run the application, jump to [Running the client application](#running-the-client-application) and run the application after cloning the repo.

The source code for this entire exercise is [available in Github for reference](https://github.com/cloudentity/ce-samples-mtls-demo/tree/master/sample-nodejs-mtls-oauth-client)

```bash
git clone https://github.com/cloudentity/ce-samples-mtls-demo.git
```

The repo contains several example projects. Change directory into the sample nodejs oauth client directory
```bash
cd ce-samples-mtls-demo/sample-nodejs-mtls-oauth-client
```

### Building the Node.js client application

First, in `index.js` we import the required required packages.

``` javascript
var axios = require('axios');
var qs = require('qs');
var express = require('express');
var app = express();
var jwt_decode = require('jwt-decode');
var fs = require('fs');
var https = require('https');

var mustacheExpress = require('mustache-express');
var bodyParser = require('body-parser');
var path = require('path')
require('dotenv').config();
```

We then [set up](https://github.com/cloudentity/sample-go-mtls-oauth-client/blob/master/main.go#L193) the express app to serve some views and html pages.

```javascript
app.set('views', `${__dirname}/views`);
app.set('view engine', 'mustache');
app.engine('mustache', mustacheExpress());
app.use (bodyParser.urlencoded( {extended : true} ) );
app.use(express.static(path.join(__dirname, "/public")));
```

We [get our](https://github.com/cloudentity/ce-samples-mtls-demo/blob/017a33ae63334789bbc9a87f6894a68cca431167/sample-nodejs-mtls-oauth-client/index.js#L24) client credentials and OAuth token URL for our non-mTLS application from our environment variables.
```javascript
const client_id = process.env.OAUTH_CLIENT_ID; 
const client_secret = process.env.OAUTH_CLIENT_SECRET; 
const token_url = process.env.OAUTH_TOKEN_URL; 
const auth_token = Buffer.from(`${client_id}:${client_secret}`, 'utf-8').toString('base64');
```

Using Mutual-TLS requires that we use our certificate and public key so we [read these](https://github.com/cloudentity/ce-samples-mtls-demo/blob/017a33ae63334789bbc9a87f6894a68cca431167/sample-nodejs-mtls-oauth-client/index.js#L30) from the file system and use them when making requests requiring mTLS and we initialize the `https.Agent`. We also read in our environment variables that will be used with our mTLS OAuth server. 
```javascript 
const httpsAgent = new https.Agent({
  cert: fs.readFileSync('full_chain.pem'),
  key: fs.readFileSync('acp_key.pem'),
});

const mtls_client_id = process.env.MTLS_OAUTH_CLIENT_ID; 
const mtls_token_url = process.env.MTLS_OAUTH_TOKEN_URL; 
```


We [set our port](https://github.com/cloudentity/ce-samples-mtls-demo/blob/00aad5ee9ab3074c0904fc6725dda24ce7838837/sample-nodejs-mtls-oauth-client/index.js#L39) and log the URL for the starting point of our application. We also set a `/health` endpoint just for verifying that everything is up and running.
```javascript
const port = process.env.PORT;
app.listen(port);

console.log(`Server listening at http://localhost:${port}/home`);

app.get('/health', function (req, res) {
  res.send('Service is alive and healthy')
});
```

Next, we set up our primary application routes to serve traffic for the OAuth flow.

We [define](https://github.com/cloudentity/ce-samples-mtls-demo/blob/00aad5ee9ab3074c0904fc6725dda24ce7838837/sample-nodejs-mtls-oauth-client/index.js#L48) a `/home` route to render the home page which will be the kick off point for retrieving an access token. 
```javascript
app.get('/home', function(req, res) {
  res.render('home', {} )
})

```

Once the application is running and the end user visits `http://localhost:5002/home` the user is presented with the following UI.
![token access ui](images/mtls-ui.png)

The home page displays links for fetching an access token through traditional OAuth 2.0 client credentials flow. Additonally, we can choose to get a certificate bound access token using mTLS as shown in the screenshot below. 

When the user selects `Get Access Token` from the UI the route `/auth` is called which fetches a regular access token that is not certificate bound. Here we are using `client_credentials` grant type. We then decode the value and display the decoded token in the UI.

```javascript

app.get('/auth', function(req, res) {
  getAuth().then(value => {
   if(value !== undefined) {
     var decoded = jwt_decode(value);
    res.render('home', {accessToken: JSON.stringify(decoded, null, 4)} )
   } else {
     res.send("No token fetched!")
   }
 }, err => {
   res.send("Unable to fetch token!")
 })
 
});

const getAuth = async () => {
try {
 const data = qs.stringify({'grant_type':'client_credentials'});
 const response = await axios.post(token_url, data, {
   headers: { 
     'Authorization': `Basic ${auth_token}`,
     'Content-Type': 'application/x-www-form-urlencoded' 
   }
 })
 return response.data.access_token; 
}catch(error){
 console.log(error);
}
}
```

Now we will fetch a certificate bound access token. When the user clicks `Get Certificate Bound Access Token` from the UI the route `/mtlsauth` is called which fetches a certificate bound access token. The `getMtlsAuth` function is called. [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) states `For all requests to the authorization server utilizing mutual-TLS client authentication, the client MUST include the "client_id"` so we pass in the client ID. We also use our `httpsAgent` which will include our certificate and public key.

```javascript
app.get('/mtlsauth', function (req, res) {
  getMtlsAuth().then(value => {
    if (value !== undefined) {
      var decoded = jwt_decode(value);
      res.render('home', { certificate_bound_access_token: JSON.stringify(decoded, null, 4) })
    } else {
      res.send("No token fetched!")
    }
  }, err => {
    res.send("Unable to fetch token!")
  })
});

const getMtlsAuth = async () => {
  try {
    const data = qs.stringify({ 'grant_type': 'client_credentials', 'client_id': mtls_client_id });

    const httpOptions = {
      url: mtls_token_url,
      method: "POST",
      httpsAgent: httpsAgent,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      data: data
    }

    const response = await axios(httpOptions)
    return response.data.access_token;
  } catch (error) {
    console.log(error);
  }
}

```


After getting a certificate bound access token, the user can then access protected resource by clicking the `Call Resource server with Certificate Bound Access Token` button on the UI. The `/mtls-resource` handler is called which then calls the protectes resource API including the certificate bound access token in the `Authorization` header. Once the response is returned the response from the protected resource is then rendered. If access to the protected resource is allowed we display the JSON response. Otherwise, we display an error that the protected resource access was not authorized. 

```javascript
const resource_url = process.env.MTLS_RESOURCE_URL; // Resource server URL

app.get('/mtls-resource', function (req, res) {
  getMtlsAuth().then(value => {
    if (value !== undefined) {
      var decoded = jwt_decode(value);
      callResourceServerMtlsAPI(value).then(value => {
        if (value !== undefined) {
          res.render('home', { mtls_resource: JSON.stringify(value, null, 4) })
        } else {
          res.send("No response fetched!")
        }
      }, err => {
        res.send("Unable to fetch the resource!")
      })
    }
  });
});

const callResourceServerMtlsAPI = async (accessToken) => {
  try {
    const httpOptions = {
      url: resource_url,
      method: "GET",
      httpsAgent: httpsAgent,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + accessToken
      }
    }

    const result = await axios(httpOptions)
    return result.data;
  } catch (error) {
    console.log(error);
  }
}
```

The user can also try and fetch the protected resource using a different certificate. Because we are using Mutual-TLS, if we use a different certificate then the client application will be unable to access the resource and an error will be displayed.
```javascript
const callResourceServerMtlsAPiAsRogueCaller = async (accessToken) => {
  try {
    const httpOptions = {
      url: resource_url,
      method: "GET",
      httpsAgent: rogueHttpsAgent,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + accessToken
      }
    }

    const result = await axios(httpOptions)
    return result;

  } catch (error) {
    console.log(error);
    return error;

  }
}
```

### Running the client application
Go to the root of the project `sample-nodejs-mtls-oauth-client`. From the root of the repo enter the following in terminal.
```bash
cd sample-nodejs-mtls-oauth-client
```

In the `.env` file enter the following
 - OAUTH_CLIENT_ID="`<your oauth client id that is not using mtls>`"
 - OAUTH_CLIENT_SECRET="`<your oauth client secret that is not using mtls>`"
 - OAUTH_TOKEN_URL="`<your oauth client token url that is not using mtls>`"
 - MTLS_OAUTH_CLIENT_ID="`<your oauth client id that is using mtls>`"
 - MTLS_OAUTH_TOKEN_URL="`<your oauth client token url that is using mtls>`"
 - MTLS_RESOURCE_URL="`<your protected resource API URL>`"

Once you have filled in the environment variables run the application by entering the following in the terminal:
```bash
npm start
```


