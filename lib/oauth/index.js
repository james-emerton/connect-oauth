var sys = require('sys'),
    querystring = require('querystring'),
    url = require('url'),
    oauth = require('oauth/oauth_services'), 
    join = require('path').join,
    connect = require('connect'),
    errors = require('oauth/oauth_error');

exports.errors = errors;

 /**
  * Initialize Oauth options.
  *
  * Options:
  *

  *   - request_token_url        'web path for the request token url endpoint, default: <realm>/request_token'
  *   - authorize_url            'web path for the authorize form, default: <realm>/authorize' (get/post)
  *   - access_token_url         'web path for the access token url endpoint, default: <realm>/access_token'
  *   - authorize_form_provider  'function to render a authentication form'
  *   - authorize_provider       'function to validate user credentials'
  *   - oauth_provider           'db instance providing needed authentication mechanisms'
  *
  * @param  {hash} options
  * @api private
  **/
var OAuth = exports.OAuth = function OAuth(options) {
    options = options || {};
    // Ensure we have default values and legal options
    if(!options.realm)
        throw Error("OAuth realm has not been defined");

    var plugin = this,
        self = this,
        realm = url.parse(options.realm),

        request_token_url = options.request_token_url
                            || join(realm.pathname, '/request_token'),

        authorize_url     = options.authorize_url
                            || join(realm.pathname, '/authorize'),

        access_token_url  = options.access_token_url
                            || join(realm.pathname, '/access_token'),

        protocol = options.protocol || realm.protocol.substr(0, realm.protocol.length-1),

        authorize_form_provider = options.authorize_form_provider,
        
        authorize_provider = options.authorize_provider;
  
    // Both authorize handler and oauth provider must be provided
    if(!authorize_form_provider || !authorize_provider)
        throw Error("authorize_form_provider and authorize_provider are required");

    if(!options.oauth_provider)
        throw Error("No OAuth provider provided");

    // Set up the OAuth provider and data source
    this.oauth_service = new oauth.OAuthServices(options['oauth_provider']);
    this.realm = options.realm;

    // Initialize the connect.Server subclass...
    connect.Server.call(this, [
        // Decode the request body...
        connect.bodyDecoder(),

        // Add request.protocol...
        function(req, res, next) {
            if(!req.protocol)
                req.protocol = protocol;
            next();
        }
    ]);

    this.use(request_token_url, function(req, resp, next) {
        self.requestToken(req, resp, next);
    });

    this.use(authorize_url, function(req, resp, next) {
        if(req.method == 'POST') {
            authorize_provider(req, resp, function(err, user) {
                if(err)
                    next(err);
                else
                    self.authorizeToken(user, req.body.oauth_token, resp, next);
            });
        }
        else
            authorize_form_provider(req, resp, next);
    });

    this.use(access_token_url, function(req, resp, next) {
        self.accessToken(req, resp, next);
    });

    this.use('/', function(req, resp, next) {
        self.verifyRequest(req, resp, next);
    });

    // Error handler...
    this.use('/', function(err, req, res, next) {
        self.handleError(err, req, res, next);
    });
}

sys.inherits(OAuth, connect.Server);

/**
OAuth Methods Handle the Request token request
**/
OAuth.prototype.requestToken = function(request, response, next) { 
    this.oauth_service.requestToken(request, function(err, result) {    
      if(err) {
          next(err);
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
OAuth.prototype.authorizeToken = function(user, oauth_token, res, next) {
    this.oauth_service.authorizeToken(user, oauth_token, function(err, result) {
        if(err) {
            next(err);
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
OAuth.prototype.accessToken = function(req, resp, next) {
    this.oauth_service.accessToken(req, function(err, result) {
        if(err) {
            next(err);
        }
        else {
            resp.writeHead(200,
                {'Content-Type': 'application/x-www-form-urlencoded'});
            resp.end(querystring.stringify({
                    oauth_token: result.token,
                    oauth_token_secret: result.token_secret
                }));
        }
    });
}

OAuth.prototype.verifyRequest = function(req, resp, next) {
    this.oauth_service.authorize(req, next);
}

OAuth.prototype.handleError = function(err, req, res, next) {
    var headers = {
        'Content-Type': 'text/plain',
    };

    if(err.statusCode == 401)
        headers['WWW-Authenticate'] = 'OAuth realm="'+this.realm+'"';

    res.writeHead(err.statusCode || 500, headers);
    res.end(err.message || err);
}

module.exports.createProvider = function(options) {
    return new OAuth(options);
}

// Generate a new random token (or token secret)
module.exports.generateToken = function(length, chars) {
    chars = chars || "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
    var result = '';
    for(var i = 0; i < length; ++i)
        result += chars[Math.floor(Math.random() * chars.length)]
    return result;
}
