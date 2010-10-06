sys = require('sys');
var oauth = require('oauth/oauth_services'), 
  errors = require('oauth/oauth_error'),
  querystring = require('querystring')
  , url = require('url')
  ;

// NB: Global s/b deprecated
var plugin = null;


 /**
  * Initialize Oauth options.
  *
  * Options:
  *

  *   - request_token_url        'web path for the request token url endpoint, default: /oauth/request_token'
  *   - authorize_url            'web path for the authorize form, default: /oauth/authorize' (get/post)
  *   - access_token_url         'web path for the access token url endpoint, default: /oauth/access_token'
  *   - authenticate_provider    'function to render a authentication form'
  *   - authorize_provider       'function to handle the authorization of the user and application'
  *   - oauth_provider           'db instance providing needed authentication mechanisms'
  *
  * @param  {hash} options
  * @api private
  **/
exports.OAuth = function OAuth(options) {
    options = options || {};
    // Ensure we have default values and legal options
    options['request_token_url'] = options['request_token_url'] || '/oauth/request_token';
    options['authorize_url'] = options['authorize_url'] || '/oauth/authorize';
    options['access_token_url'] = options['access_token_url'] || '/oauth/access_token';
    options['assume_protocol'] = options['assume_protocol'] || 'http';
  
    // Both authorize handler and oauth provider must be provided
    if(options['authenticate_provider'] == null) throw Error("No Authentication provider provided");
    if(options['authorize_provider'] == null) throw Error("No Authorization provider provided");
    if(options['oauth_provider'] == null) throw Error("No OAuth provider provided");
    if(options['authorization_finished_provider'] == null) throw Error("No finished authentication provider provided");
    // Mixin in all the options (setting them)
    for(var name in options) {
      this[name] = options[name];
    }
  
    // Set up the OAuth provider and data source
    this.oauth_service = new oauth.OAuthServices(options['oauth_provider']);
  
    // Define reference
    plugin = this;
  
    return function(request, response, next) {
        if(!request.protocol)
            request.protocol = options.assume_protocol;
  
        // Dispatch OAuth requests appropriately...
        switch(url.parse(request.url).pathname) {
        case plugin.request_token_url:
            // Handle token request...
            requestToken(plugin, request, response);
            break;
  
        case plugin.authorize_url:
            if(request.method == 'POST')
                // Authenticate token...
                handleAuthorization(plugin, request, response);
            else
                // Display authentication form...
                plugin.authenticate_provider(request, response, next);
            break;
  
        case plugin.access_token_url:
            accessTokenMethod(request, response, next);
            break;
  
        default:
            // TODO: Test the signature!
            next();
      }
    }
}

/**
OAuth Methods Handle the Request token request
**/
function requestToken(plugin, request, response) { 
    plugin.oauth_service.requestToken(request, function(err, result) {    
      if(err) {
        response.writeHead(err.statusCode, { 'Content-Type': 'text/plain' });
        response.end(err.message);
      }
      else {
        response.writeHead(200, {'Content-Type':'application/x-www-form-urlencoded'});
        response.end(["oauth_token=" + result["token"],
            "oauth_token_secret=" + result["token_secret"],
            "oauth_callback_confirmed=" + result["oauth_callback_confirmed"]
            ].join("&"));            
      }
    });
};


/**
OAuth Methods Handle the Authorization form postback
**/
function handleAuthorization(plugin, req, res) {
    var self = this,
        params = req.body,
        oauth_token = req.body.oauth_token,
        verifier = req.body.verifier;
    
    plugin.oauth_service.authorizeToken(req, oauth_token, function(err, result) {
        if(err) {
            // TODO: Allow some customization...
            res.writeHead(err.statusCode, {'Content-Type': 'text/plain'});
            res.end(err.message);
        }
        else if(result.callback && result.callback != "oob") {
            var callback = querystring.unescape(result.callback),
                redirect_url = url.parse(callback, true);

            redirect_url.query = redirect_url.query || {};
            redirect_url.query.oauth_token = result.token;
            redirect_url.query.oauth_verifier = result.verifier;

            res.writeHead(307, {'Location': url.format(redirect_url)});
            res.end();
        }
        else {
            // Callback is oob, just return a 200 for now
            // TODO: Allow the application to display a user interface here
            res.writeHead(200, {'Content-Type':'application/x-www-form-urlencoded'});
            res.end([
                'oauth_token='+result.token,
                'oauth_verifier='+result.verifier].join('&'));
        }
    });
}

/**
OAuth Methods Handle the Retrieve Access token
**/
function accessTokenMethod(req, resp, next) {
    plugin.oauth_service.accessToken(req, function(err, result) {
        if(err) {
            resp.writeHead(err.statusCode, {'Content-Type': 'text/plain'});
            resp.end(err.message);
        }
        else {
            resp.writeHead(200,
                {'Content-Type': 'application/x-www-form-urlencoded'});
            resp.end(querystring.stringify({
                    oauth_token: result.access_token,
                    oauth_token_secret: result.token_secret
                }));
        }
    });
};

///**
//  Global Defines for oauth methods
//**/
//oauth_get = function(path, options, fn) {  
//  var args = Array.prototype.slice.call(arguments, 1);
//  fn = args.pop();
//  options = args.length ? args.shift() : null;
//  // Let's wrap the function call in our oauth code
//  get(path, options, function() { 
//    // Ensure context is kept
//    var self = this;  
//    var self_arguments = Array.prototype.slice.call(arguments, 0);
//    var finalPath = this.url.href.split(/\?/)[0];        
//    // Attempt authorization
//    plugin.oauth_service.authorize(self.method, 'http', self.headers['host'], finalPath, self.headers, self.params, function(err, result) {
//      err != null ? self.halt(err.statusCode, err.message) : fn.apply(self, [result.id].concat(self_arguments));
//    });
//  });
//};
//
//oauth_post = function(path, options, fn) {  
//  var args = Array.prototype.slice.call(arguments, 1);
//  fn = args.pop();
//  options = args.length ? args.shift() : null;
//  // Let's wrap the function call in our oauth code
//  post(path, options, function() { 
//    // Ensure context is kept
//    var self = this;  
//    var self_arguments = Array.prototype.slice.call(arguments, 0);
//    var finalPath = this.url.href.split(/\?/)[0];        
//    // Attempt authorization
//    plugin.oauth_service.authorize(self.method, 'http', self.headers['host'], finalPath, self.headers, self.params, function(err, result) {
//      err != null ? self.halt(err.statusCode, err.message) : fn.apply(self, [result.id].concat(self_arguments));
//    });
//  });
//};
//
//oauth_put = function(path, options, fn) {  
//  var args = Array.prototype.slice.call(arguments, 1);
//  fn = args.pop();
//  options = args.length ? args.shift() : null;
//  // Let's wrap the function call in our oauth code
//  put(path, options, function() { 
//    // Ensure context is kept
//    var self = this;  
//    var self_arguments = Array.prototype.slice.call(arguments, 0);
//    var finalPath = this.url.href.split(/\?/)[0];        
//    // Attempt authorization
//    plugin.oauth_service.authorize(self.method, 'http', self.headers['host'], finalPath, self.headers, self.params, function(err, result) {
//      err != null ? self.halt(err.statusCode, err.message) : fn.apply(self, [result.id].concat(self_arguments));
//    });
//  });
//};
//
//oauth_del = function(path, options, fn) {  
//  var args = Array.prototype.slice.call(arguments, 1);
//  fn = args.pop();
//  options = args.length ? args.shift() : null;
//  // Let's wrap the function call in our oauth code
//  del(path, options, function() { 
//    // Ensure context is kept
//    var self = this;  
//    var self_arguments = Array.prototype.slice.call(arguments, 0);
//    var finalPath = this.url.href.split(/\?/)[0];        
//    // Attempt authorization
//    plugin.oauth_service.authorize(self.method, 'http', self.headers['host'], finalPath, self.headers, self.params, function(err, result) {
//      err != null ? self.halt(err.statusCode, err.message) : fn.apply(self, [result.id].concat(self_arguments));
//    });
//  });
//};
