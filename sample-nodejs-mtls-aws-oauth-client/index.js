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


app.set('views', `${__dirname}/views`);
app.set('view engine', 'mustache');
app.engine('mustache', mustacheExpress());
app.use (bodyParser.urlencoded( {extended : true} ) );
app.use(express.static(path.join(__dirname, "/public")));

app.get('/home', function(req, res) {
  res.render('home', {pageTitle: "Enter Your Name"} )
})

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


const client_id = process.env.OAUTH_CLIENT_ID; // Your client id
const client_secret = process.env.OAUTH_CLIENT_SECRET; // Your secret
const token_url = process.env.OAUTH_TOKEN_URL; // Your secret
const auth_token = Buffer.from(`${client_id}:${client_secret}`, 'utf-8').toString('base64');

const httpsAgent = new https.Agent({
  cert: fs.readFileSync('acp_cert.pem'),
  key: fs.readFileSync('acp_key.pem'),
});


const mtls_client_id = process.env.MTLS_OAUTH_CLIENT_ID; // Your client id
const mtls_client_secret = process.env.MTLS_OAUTH_CLIENT_SECRET; // Your secret
const mtls_token_url = process.env.MTLS_OAUTH_TOKEN_URL; // Your secret
const mtls_auth_token = Buffer.from(`${mtls_client_id}:${mtls_client_secret}`, 'utf-8').toString('base64');

const getMtlsAuth = async () => {
  try{
    const data = qs.stringify({'grant_type':'client_credentials', 'client_id': mtls_client_id});

    const httpOptions = {
      url: mtls_token_url,  
      method: "POST",
      httpsAgent : httpsAgent,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded' 
    },
    data: data
    }

    const response = await axios(httpOptions)
    return response.data.access_token;
  } catch(error){
    console.log(error);
  }
}


const resource_url = process.env.MTLS_RESOURCE_URL; // Your resource URL

const callResourceServerMtlsAPi = async (accessToken) => {
  try {
   const httpOptions = {
    url: resource_url,  
    method: "GET",
    httpsAgent : httpsAgent,
    headers: {
      'Content-Type': 'application/json' ,
      'Authorization': 'Bearer ' + accessToken
    }
  }
  
  const result = await axios(httpOptions)
    return result.data;  
  }catch(error){
    console.log(error);
  }

}

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

app.get('/mtlsauth', function(req, res) {
  getMtlsAuth().then(value => {
   if(value !== undefined) {
     var decoded = jwt_decode(value);
     res.render('home', {certificate_bound_access_token: JSON.stringify(decoded, null, 4)} )
   } else {
     res.send("No token fetched!")
   }
 }, err => {
   res.send("Unable to fetch token!")
 })
});



app.get('/mtls-resource', function(req, res) {
  getMtlsAuth().then(value => {
    if(value !== undefined) {
        var decoded = jwt_decode(value);
        callResourceServerMtlsAPi(value).then(value => {
        if(value !== undefined) {
          res.render('home', {mtls_resource: JSON.stringify(value, null, 4)} )
        } else {
          res.send("No response fetched!")
        }
      }, err => {
        res.send("Unable to fetch token!")
      })
  }
  });
});

app.get('/mtls-resource-roguecaller', function(req, res) {
  getMtlsAuth().then(value => {
    if(value !== undefined) {
        var decoded = jwt_decode(value);
        callResourceServerMtlsAPiAsRogueCaller(value).then(value => {
        if(value !== undefined) {
          res.render('home', {mtls_resource_rogue_caller: value} )
        } else {
          res.send("No response fetched!")
        }
      }, err => {
        res.send("Unable to fetch token!")
      })
  }
  });
});

const rogueHttpsAgent = new https.Agent({
  cert: fs.readFileSync('api-server-cert.pem'),
  key: fs.readFileSync('api-server-key.pem'),
});


const callResourceServerMtlsAPiAsRogueCaller = async (accessToken) => {
  try {
    const httpOptions = {
    url: resource_url,  
    method: "GET",
    httpsAgent : rogueHttpsAgent,
    headers: {
      'Content-Type': 'application/json' ,
      'Authorization': 'Bearer ' + accessToken
    }
  }
 
  const result = await axios(httpOptions)
  return result;
   
  } catch(error)
  {
     console.log(error);
   return error;

  }

}


app.get('/health', function(req, res) {
    res.send('Service is alive and healthy')
});

app.listen(5002);
console.log("Server listening at http://localhost:5002/");
