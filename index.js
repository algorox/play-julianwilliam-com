require('dotenv').config();
var saml2 = require('saml2-js');
var path = require('path');
var express = require('express');
var app = express();
var ejsLayouts = require('express-ejs-layouts');
var morgan = require('morgan');
var bodyParser = require('body-parser');

var PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: false }))
app.use(morgan('dev'));

// static files
app.use(express.static(path.join(__dirname, 'public')));

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(ejsLayouts);
app.set('layout extractScripts', true);

// parse application/json
app.use(bodyParser.json());

//SAML Set-up
var session_index;
var name_id;

// Create service provider - HTTPS

var sp_options = {
  entity_id: process.env.SP_HOST + ':' + '/metadata.xml',
  assert_endpoint: process.env.SP_HOST + ':' + '/assert'
};


//LOCAL HOST
/*
var sp_options = {
  entity_id: 'http://' + process.env.SP_HOST + '/metadata.xml',
  assert_endpoint: 'http://' + process.env.SP_HOST  + '/assert'
};
*/

var sp = new saml2.ServiceProvider(sp_options);

// Create identity provider
var idp_options = {
  sso_login_url: 'https://' + process.env.AUTH0_DOMAIN + '/samlp/' + process.env.AUTH0_SP_CLIENT_ID,
  //sso_logout_url: 'https://' + process.env.AUTH0_DOMAIN + '/samlp/' + process.env.AUTH0_SP_CLIENT_ID + '/logout',
  sso_logout_url: 'https://' + process.env.AUTH0_DOMAIN + '/logout',
  certificates: process.env.IDP_PEM
};
var idp = new saml2.IdentityProvider(idp_options);

// ------ Define express endpoints ------

// Endpoint to retrieve metadata
app.get('/metadata.xml', function (req, res) {
  res.type('application/xml');
  res.send(sp.create_metadata());
});

// Starting point for login
app.get('/samlLogin', function (req, res) {
  sp.create_login_request_url(idp, {}, function (err, login_url, request_id) {
    if (err != null)
      return res.send(500);
    res.redirect(login_url);
  });
});

app.get('/assert', function (req, res) {
  sp.create_login_request_url(idp, {}, function (err, login_url, request_id) {
    if (err != null)
      return res.send(500);
    res.redirect(login_url);
  });
});


// Assert endpoint for when login completes
app.post('/assert', function (req, res) {
  var options = {
    request_body: req.body,
    allow_unencrypted_assertion: true,
    require_session_index: false
  };
  sp.post_assert(idp, options, function (err, saml_response) {

    if (err) {
      //console.log('SAML post_assert error:', err);
      //return res.status(500).json(err);
      res.render('error', {
        error: JSON.stringify(err)
      });
      return;
    }

    // Save name_id and session_index for logout
    // Note: In practice these should be saved in the user session, not globally.

    var session_index = saml_response.user.session_index;
    var name = saml_response.user.name;
    var email = saml_response.user.email;
    var name_id = saml_response.user.name_id;

    res.render('assert', {
      auth0_domain: process.env.AUTH0_DOMAIN,
      auth0_sp_client_id: process.env.AUTH0_SP_CLIENT_ID,
      auth0_frontend_client_id: process.env.AUTH0_FRONTEND_CLIENT_ID,
      api_audience: process.env.API_AUDIENCE,
      scope: process.env.SPA_SCOPES,
      nameid: name_id,
      sessionIndex: session_index,
      name: name,
      email: email,
      //CHANGEto HTTP WHEN SP NOT USING LOCALHOST
      base_url: process.env.SP_HOST,
      redirectUri: process.env.AUTH0_OIDC_CALLBACK_URL
      //base_url: 'http://' + process.env.SP_HOST
    });
  });
});

// Starting point for logout
app.get('/SAMLlogout', function (req, res) {
  var options = {
    name_id: name_id,
    session_index: session_index
  };

  sp.create_logout_request_url(idp, options, function (err, logout_url) {
    if (err != null)
      return res.send(500);
    res.redirect(logout_url);
  });
});


//Endpoint for when login completes successfully
app.get('/signedin', function (req, res) {

  res.render('signedin', {
    auth0_domain: process.env.AUTH0_DOMAIN,
    auth0_sp_client_id: process.env.AUTH0_SP_CLIENT_ID,
    auth0_frontend_client_id: process.env.AUTH0_FRONTEND_CLIENT_ID,
    api_audience: process.env.API_AUDIENCE,
    scope: process.env.SPA_SCOPES,
    nameid: 'You Logged in with OIDC',
    sessionIndex: 'You Logged in with OIDC',
    name: 'test',
    email: 'test',
    //CHANGEto HTTP WHEN SP NOT USING LOCALHOST
    //base_url: 'https://' + process.env.SP_HOST
    base_url: process.env.SP_HOST,
    redirectUri: process.env.AUTH0_OIDC_CALLBACK_URL
  });
});

app.get('/logout', function (req, res) {

  res.render('logout', {


    auth0_domain: process.env.AUTH0_DOMAIN,
    auth0_frontend_client_id: process.env.AUTH0_SMS_PW_RESET_CLIENTID,
    api_audience: process.env.API_AUDIENCE,
    scope: 'openid profile email read:current_user update:current_user_metadata',
    nameid: 'You Logged in with OIDC',
    sessionIndex: 'You Logged in with OIDC',
    name: 'test',
    email: 'test',
    //CHANGEto HTTP WHEN SP NOT USING LOCALHOST
    //base_url: 'https://' + process.env.SP_HOST
    base_url: process.env.SP_HOST,
    redirectUri: process.env.AUTH0_LOGOUT_REDIRECT

  });
});

app.get('/checkout', function (req, res) {

  res.render('checkout', {
    api_services_host: process.env.API_HOST,
    auth0_domain: process.env.AUTH0_DOMAIN,
    auth0_sp_client_id: process.env.AUTH0_SP_CLIENT_ID,
    auth0_frontend_client_id: process.env.AUTH0_FRONTEND_CLIENT_ID,
    api_audience: process.env.API_AUDIENCE,
    scope: process.env.SPA_SCOPES,
    nameid: 'You Logged in with OIDC',
    sessionIndex: 'You Logged in with OIDC',
    name: 'test',
    email: 'test',
    //CHANGEto HTTP WHEN SP NOT USING LOCALHOST
    //base_url: 'https://' + process.env.SP_HOST
    base_url: process.env.SP_HOST,
    redirectUri: process.env.AUTH0_OIDC_CALLBACK_URL

  });

});

app.get('/legacyLogin', function (req, res) {

  res.render('legacyLogin', {
    legacy_login_url: process.env.LEGACY_LOGIN_URL,
  });

});

app.get('/legacyChangePassword', function (req, res) {

  res.render('legacyChangePassword', {
    legacy_change_password_url: process.env.LEGACY_CHANGE_PASSWORD_URL,
  });

});

app.get('/legacyResetPassword', function (req, res) {

  res.render('legacyResetPassword', {
    legacy_reset_password_url: process.env.LEGACY_RESET_PASSWORD_URL,
  });

});

app.get('/legacySignUp', function (req, res) {

  res.render('legacySignUp', {
    legacy_signup_url: process.env.LEGACY_SIGNUP_URL,
  });

});

app.get('/legacyDeleteUser', function (req, res) {

  res.render('legacyDeleteUser', {
    legacy_delete_user_url: process.env.LEGACY_DELETE_USER_URL,
  });

});

app.get('/pwreset', function (req, res) {

  res.render('pwreset', {


    auth0_domain: process.env.AUTH0_DOMAIN,
    auth0_frontend_client_id: process.env.AUTH0_SMS_PW_RESET_CLIENTID,
    api_audience: process.env.API_AUDIENCE,
    scope: 'openid profile email read:current_user update:current_user_metadata',
    nameid: 'You Logged in with OIDC',
    sessionIndex: 'You Logged in with OIDC',
    name: 'test',
    email: 'test',
    //CHANGEto HTTP WHEN SP NOT USING LOCALHOST
    //base_url: 'https://' + process.env.SP_HOST
    base_url: process.env.SP_HOST,
    redirectUri: process.env.REDIRECTURI_SMS_PWRESET

  });
});

app.get('/progressive-profiling', function (req, res) {


  if ((req.rawHeaders.indexOf('jwlm.com:3000')) || (req.rawHeaders.indexOf('play.julianwillam.com'))) {
    res.render('progressive-profiling', {
      auth0_domain: process.env.AUTH0_DOMAIN,
      auth0_sp_client_id: process.env.AUTH0_SP_CLIENT_ID,
      auth0_frontend_client_id: process.env.AUTH0_FRONTEND_CLIENT_ID,
      api_audience: process.env.API_AUDIENCE,
      scope: process.env.SPA_SCOPES,
      state: req.query.state,
      base_url: process.env.SP_HOST,
      redirectUri: process.env.AUTH0_OIDC_CALLBACK_URL,
      progressive_profiling_token: req.query.token,
      api_host: process.env.API_HOST
    });
  }

  else {
    res.render('error', {
      error: 'No PP for you!'
    });
  }
});

app.get('/authorisation', function (req, res) {

  res.render('authorisation', {
    auth0_domain: process.env.AUTH0_DOMAIN,
    auth0_sp_client_id: process.env.AUTH0_SP_CLIENT_ID,
    auth0_frontend_client_id: process.env.AUTH0_FRONTEND_CLIENT_ID,
    api_audience: process.env.API_AUDIENCE,
    scope: process.env.SPA_SCOPES,
    nameid: 'You Logged in with OIDC',
    sessionIndex: 'You Logged in with OIDC',
    name: 'test',
    email: 'test',
    //CHANGEto HTTP WHEN SP NOT USING LOCALHOST
    //base_url: 'https://' + process.env.SP_HOST
    base_url: process.env.SP_HOST,
    authN_redirectUri: process.env.AUTHORISATION_CALLBACK_URL
  });
});

app.get('/apiservices', function (req, res) {

  res.render('apiservices', {
    auth0_domain: process.env.AUTH0_DOMAIN,
    auth0_frontend_client_id: process.env.AUTH0_FRONTEND_CLIENT_ID,
    api_services_redirectUri: process.env.API_SERVICES_CALLBACK_URL,
    api_services_scopes: process.env.API_SERVICES_SCOPE,
    api_services_audience: process.env.API_SERVICES_AUDIENCE,
    nameid: 'You Logged in with OIDC',
    sessionIndex: 'You Logged in with OIDC',
    name: 'test',
    email: 'test',
    //CHANGEto HTTP WHEN SP NOT USING LOCALHOST
    //base_url: 'https://' + process.env.SP_HOST
    base_url: process.env.SP_HOST,
    api_services_host: process.env.API_HOST
  });
});

app.get('/passwordless_redirect', function (req, res) {

  if (req.query.pwlessStart === 'true' && req.query.token) {
    res.render('passwordless_redirect', {
      login_hint: req.query.token,
      pwlessStart: true,
      state: req.query.state,
      auth0_domain: process.env.AUTH0_DOMAIN,
      auth0_frontend_client_id: process.env.AUTH0_PWLESS_CLIENTID,
      api_audience: process.env.API_AUDIENCE,
      redirectUri: process.env.AUTH0_PWLESS_SIGNIN_URI,
    });
  }

  else {
    res.render('passwordless_redirect', {
      login_hint: 'notused',
      pwlessStart: false,
      state: req.query.state,
      auth0_domain: process.env.AUTH0_DOMAIN,
      auth0_frontend_client_id: process.env.AUTH0_PWLESS_CLIENTID,
      api_audience: process.env.API_AUDIENCE,
      redirectUri: process.env.AUTH0_PWLESS_SIGNIN_URI,
    });
  }
});

app.get('/', function (req, res) {

  res.render('index', {
    auth0_domain: process.env.AUTH0_DOMAIN,
    auth0_sp_client_id: process.env.AUTH0_SP_CLIENT_ID,
    auth0_frontend_client_id: process.env.AUTH0_FRONTEND_CLIENT_ID,
    api_audience: process.env.API_AUDIENCE,
    scope: process.env.SPA_SCOPES,
    base_url: process.env.SP_HOST,
    redirectUri: process.env.AUTH0_OIDC_CALLBACK_URL,
    api_services_redirectUri: process.env.API_SERVICES_CALLBACK_URL,
    authN_redirectUri: process.env.AUTHORISATION_CALLBACK_URL,
    api_services_scopes: process.env.API_SERVICES_SCOPE,
    api_services_audience: process.env.API_SERVICES_AUDIENCE,
    api_services_host: process.env.API_HOST,
    saml_connection: 'jwlm-saml-idp',
    auth0_sms_pwreset_clientID: process.env.AUTH0_PWLESS_CLIENTID,
    auth0_sms_pwreset_redirecturi: process.env.REDIRECTURI_SMS_PWRESET,
  });

});

app.get('/error', function (req, res) {

  if (req.query.error) {
    res.render('error', {
      error: req.query.error,
    });
  }

  else {
    res.render('error', {
      error: 'Unknown Error - contact julian@auth0com',
    });
  }

});

app.listen(PORT, function () {
  console.log('SP server, listening on port', PORT);
});
