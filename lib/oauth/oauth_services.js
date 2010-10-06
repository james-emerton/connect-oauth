var sys = require('sys'),
    querystring = require('querystring'),
    escape = querystring.escape,
    crypto = require('oauth/crypto/sha1'),
    urlparse = require('url').parse,
    errors = require('oauth/oauth_error');

var OAuthServices = exports.OAuthServices = function(provider) {
  this.provider = provider;
  /**
    Ensure the provider has the correct functions
  **/
  //['previousRequestToken', 'tokenByConsumer', 'applicationByConsumerKey', 'validToken', 'authenticateUser', 'generateRequestToken', 'generateAccessToken', 'cleanRequestTokens', 'validateNotReplay', 'associateTokenToUser', 'tokenByTokenAndVerifier', 'userIdByToken'].forEach(function(method) {
    //if(!(Object.prototype.toString.call(provider[method]) === "[object Function]"))
        //throw Error("Data provider must provide the method "+method);
  //});  
}

/**
  OAuth Methods
**/  
OAuthServices.prototype.authorize = function(method, protocol, url, path, headers, parameters, callback) {
  var requestParameters = this.parseParameters(headers, parameters);
  if(requestParameters == null) { callback(new errors.OAuthBadRequestError("Missing required parameters"), null); return };  

  try {
    // Ensure correct parameters are available
    this.validateParameters(requestParameters, ['oauth_consumer_key', 'oauth_token',
            'oauth_signature_method', 'oauth_signature',
            'oauth_timestamp', 'oauth_nonce'])
  }
  catch(err) {
      callback(err, null);
      return
  }    

  var self = this;
  
  // Check if token is valid
  self.provider.validToken(requestParameters.oauth_token, function(err, token) {
    if(err) {
      callback(new errors.OAuthProviderError('Invalid / expired Token'), null);        
    } else {                
      if(token.access_token == null || token.token_secret == null) { callback(new errors.OAuthProviderError("provider: validToken must return a object with fields [access_token, token_secret]"), null); return;}
      self.provider.validateNotReplay(requestParameters.oauth_token, requestParameters.oauth_timestamp, requestParameters.oauth_nonce, function(err, result) {
        if(err) {
          callback(new errors.OAuthUnauthorizedError('Invalid / used nonce'), null);
        } else {
          self.provider.getConsumerByKey(token.consumer_key, function(err, user) {
            if(user.consumer_key == null || user.secret == null) { callback(new errors.OAuthProviderError("provider: getConsumerByKey must return a object with fields [token, secret]"), null); return;}
            // If we have a user for this consumer key let's calculate the signature
            var calculatedSignature = self.calculateSignature(method, protocol, url, path, requestParameters, token.token_secret, user.secret);            
            // Check if the signature is correct and return a access token
            if(calculatedSignature == requestParameters.oauth_signature) {
              // Fetch the user id to pass back
              self.provider.userIdByToken(requestParameters.oauth_token, function(err, doc) {
                if(doc.id == null) { callback(new errors.OAuthProviderError("provider: userIdByToken must return a object with fields [id]"), null); return;}
                // Return the user id to the calling function
                callback(null, doc);                
              });
            } else {
              callback(new errors.OAuthBadRequestError("Invalid signature"), null);
            }          
          });
        }
      });
    }
  });
}

// Authenticate the user and validate the request token
OAuthServices.prototype.authorizeToken = function(req, oauthToken, callback) {
  this.provider.authorizeToken(req, oauthToken, function(err, result) {
    if(err) {
        callback(err, null);
        return;
    };

    if(!result.token || !result.verifier || !result.callback) {
        callback(new errors.OAuthProviderError(
            "authorizeToken must return a object with "+
            "fields [token, verifier, callback]"), null);
        return;
    }

    callback(null, result);      
  });
}

OAuthServices.prototype.requestToken = function(request, callback) { 
    var self = this,
      method = request.method,
      // TODO: protocol is an assumption!!
      protocol = request.protocol,
      url = request.headers['host'],
      path = require('url').parse(request.url).pathname,
      headers = request.headers,
      parameters = request.body,
      requestParameters = this.parseParameters(request);

    // Ensure correct parameters are available
    try {
    this.validateParameters(requestParameters, ['oauth_consumer_key',
            'oauth_signature_method', 'oauth_signature',
            'oauth_timestamp', 'oauth_nonce', 'oauth_callback']);
    }
    catch(err) {
      callback(err, null);
      return
    }    

    // Fetch the secret and token for the user
    this.provider.getConsumerByKey(requestParameters.oauth_consumer_key,
        function(err, user) {
            if(err) {
                callback(new errors.OAuthProviderError('Invalid Consumer Key'));
                return;
            }

            if(user.consumer_key == null || user.secret == null) {
                callback(new errors.OAuthProviderError(
                    "provider: getConsumerByKey must return an "+
                    "object with fields [consumer_key, secret]"));
                  return;
            }

            // If we have a user for this consumer key let's calculate the signature
            var calculatedSignature = self.calculateSignature(method, protocol,
                    url, path, requestParameters, user.token, user.secret);

            // Check if the signature is correct and return a request token
            if(calculatedSignature != requestParameters.oauth_signature) {
                callback(new errors.OAuthUnauthorizedError("Invalid signature"));
                return;
            }

            self.provider.generateRequestToken(
                requestParameters.oauth_consumer_key,
                requestParameters.oauth_callback,
                function(err, result) {
                    if(err) {
                        callback(new errors.OAuthProviderError("internal error"));
                    }
                    else if(result.token == null || result.token_secret == null) {
                        callback(new errors.OAuthProviderError(
                            "provider: generateRequestToken must return a object "+
                            "with fields [token, token_secret]"), null);
                        return;
                    }
                    else {
                        result['oauth_callback_confirmed'] = true;
                        callback(null, result);                
                    }
            });
    });
}

OAuthServices.prototype.accessToken = function(request, callback) { 
  var params = this.parseParameters(request);

  // Ensure correct parameters are available
  try {
    this.validateParameters(params, ['oauth_consumer_key', 'oauth_token',
            'oauth_signature_method', 'oauth_signature', 'oauth_timestamp',
            'oauth_nonce', 'oauth_verifier'])
  }
  catch(err) {
      callback(err);
      return
  }
  var self = this;

  // Fetch the secret and token for the user
  this.provider.getConsumerByKey(params['oauth_consumer_key'], function(err, consumer) {
      if(err) {
        callback(new errors.OAuthProviderError('Invalid Consumer Key'), null);        
        return;
      }

      if(!consumer.consumer_key || !consumer.secret) {
          callback(new errors.OAuthProviderError("provider: getConsumerByKey must return a object with fields [token, secret]"), null);
          return;
      }

      // Retrieve token object...
      self.provider.getTokenByKey(params.oauth_token, function(err, token) {
          if(err) {
              callback(new errors.OAuthProviderError('Invalid / expired Token'));
              return;
          }

          if(!token.token || !token.token_secret || !token.verifier) {
              callback(new errors.OAuthProviderError("provider: tokenByConsumer "
                  +"must return a object with fields [token, token_secret, verifier]"));
              return;
          }

          if(token.token != params.oauth_token) {
              callback(new errors.OAuthUnauthorizedError("Invalid / expired Token"));
              return;
          }

          if(token.verifier != params.oauth_verifier) {
              callback(new errors.OAuthBadRequestError("Invalid verifier for token"));
              return;
          }

          var calculated_signature = self.calculateSignature(
              request.method,
              request.protocol,
              request.headers['host'],
              require('url').parse(request.url).pathname,
              params,
              token.token_secret,
              consumer.secret);

          if(calculated_signature != params.oauth_signature) {
              callback(new errors.OAuthUnauthorizedError("Invalid signature"));
              return;
          }

          self.provider.generateAccessToken(params.oauth_token,
            function(err, result) {
                if(!result.access_token || !result.token_secret) {
                    callback(new errors.OAuthProviderError(
                        "generateAccessToken must return a object with "
                        +"fields [access_token, token_secret]"));
                    return;
                }

                callback(null, result);
          });

      });
  });
}

/**
  Verify if a token exists using the verifier number and the oauth_otken
**/
OAuthServices.prototype.verifyToken = function(token, verifier, callback) {
  this.provider.tokenByTokenAndVerifier(token, verifier, function(err, token) {
    if(token.token == null || token.verifier == null) { callback(new errors.OAuthProviderError("provider: tokenByTokenAndVerifier must return a token object with fields [token, verifier]"), null); return;}
    callback(err, token);
  });
}

/**
  Fetch an associated application object and user object
**/
OAuthServices.prototype.fetchAuthorizationInformation = function(username, token, callback) {
  this.provider.fetchAuthorizationInformation(username, token, function(err, application, user) {
    if(application.title == null || application.description == null || user.token == null || user.username == null) { callback(new errors.OAuthProviderError("provider: getConsumerByKey must return a application object with fields [title, description] and a user object with fields [username, token]"), null); return;}
    // Return the value to calling plugin
    callback(err, application, user);
  });
}

/**
  Internal Methods used for parsing etc
**/  
// TODO: Does this really need to be a member function?
OAuthServices.prototype.validateParameters = function(parameters, requiredParameters) {
  if(!parameters) {
      throw(new errors.OAuthBadRequestError("Missing required parameter"));
  }

  requiredParameters.forEach(function(requiredParameter) {
    if(parameters[requiredParameter] == null)
        throw(new errors.OAuthBadRequestError(
            "Missing required parameter: "+requiredParameter));
  });
  return true;
}

// Return the signature base string...
function getBaseString(method, protocol, url, path, parameters) {
    // TODO: We're missing parameters...
    // Build a list of encoded key-values
    var values = [];
    for(p in parameters) {
        if(p != 'oauth_signature')
            values.push(escape(p)+'='+escape(parameters[p]));
    }

    values = escape(values.sort().join('&'));

    return [
        method.toUpperCase(),
        escape(protocol.toLowerCase()+'://'+url.toLowerCase()+path),
        ].concat(values).join('&');
}

OAuthServices.prototype.calculateSignature = function(method, protocol, url, path, parameters, token, secret) {
    var baseString = getBaseString(method, protocol, url, path, parameters),
        key = escape(secret||'')+'&'+escape(token||'');

  switch(parameters['oauth_signature_method']) {
      case 'HMAC-SHA1':
        return crypto.SHA1.b64_hmac_sha1(key, baseString)+'=';
      case 'RSA-SHA1':
        throw('RSA-SHA1 signature method is unimplemented');
      case 'PLAINTEXT':
        // TODO: We can actually skip this entirely...
        return key;
  }
}

OAuthServices.prototype.parseParameters = function(req) {
  // Try Authorization header first...
  if(req.headers['authorization'] && req.headers['authorization'].indexOf('OAuth') != -1) {
    var parameters = {};

    // Trim the strings and split the values
    req.headers['authorization']
        .substring('OAuth '.length)
        .split(',')
        .forEach(function(str) {
      var p = str.trim(),
          i = p.indexOf('=')
          pname = p.substr(0,i)
          pval = p.substr(i+1);
      parameters[pname] = querystring.unescape(pval.replace(/^"|"$/g, ''));
    });

    return parameters;
  }
  else if(req.method == 'POST' && req.body['oauth_consumer_key'])
    // POST parameters next...
    return req.body;

  else
    // Finally look in the query string...
    return urlparse(req.url, true).query;
}
