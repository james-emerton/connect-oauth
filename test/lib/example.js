//
// Implement the OAuth example provider...

var TEST_PORT = parseInt(process.env['TEST_PORT']),
    CONSUMER_KEY = 'dpf43f3p2l4k3l03',
    CONSUMER_SECRET = 'kd94hf93k423kf44',

    REQUEST_TOKEN = 'hh5s93j4hdidpola',
    REQUEST_TOKEN_SECRET = 'hdhd0244k9j7ao03',
    VERIFIER = 'hfdp7dh39dks9884',

    ACCESS_TOKEN = 'nnch734d00sl2jdk',
    ACCESS_TOKEN_SECRET = 'pfkkdhi9sl3r4s00',

    assert = require('assert'),
    connect = require('connect'),
    oauth = require('oauth');


// ExampleProvider executes the OAuth workflow as per Appendix A of the specification
function ExampleProvider() { }

ExampleProvider.prototype = {
    getConsumerByKey: function(key, callback) {
        assert.equal(key, CONSUMER_KEY);

        callback(null, {
            consumer_key: CONSUMER_KEY,
            secret: CONSUMER_SECRET
        });
    },

    generateRequestToken: function(key, oauth_callback, callback) {
        assert.equal(key, CONSUMER_KEY);
        assert.equal(oauth_callback, 'http://printer.example.com/request_token_ready');
        callback(null, {
            token: REQUEST_TOKEN,
            token_secret: REQUEST_TOKEN_SECRET,
            token_type: 'request'
        });
    },

    generateAccessToken: function(request_token, callback) {
        if(request_token != REQUEST_TOKEN)
            callback("Invalid request token");

        else
            callback(null, {
                access_token: ACCESS_TOKEN,
                token_secret: ACCESS_TOKEN_SECRET
            });
    },

    authorizeToken: function(req, oauth_token, callback) {
        if(req.body.username != 'jane' || req.body.password != 'mypassword')
            callback('Invalid username or password');
        else
            callback(null, {
                token: oauth_token,
                verifier: VERIFIER,
                callback: 'http://printer.example.com/request_token_ready'
            });
    },

    getTokenByKey: function(key, callback) {
        if(key == REQUEST_TOKEN)
            callback(null, {
                token: REQUEST_TOKEN,
                token_secret: REQUEST_TOKEN_SECRET,
                verifier: VERIFIER,
                token_type: 'request'
            });
        else
            callback('Invalid/expired token');
    },

    previousRequestToken: function() {},
    tokenByConsumer: function() {},
    validToken: function() {},
    cleanRequestTokens: function() {},
    validateNoReplay: function() {},
    associateTokenToUser: function() {},
    tokenByTokenAndVerifier: function() {},
    userIdByToken: function() {}
}


function start_server(callback) {
    var server = connect.createServer(
        connect.logger(),
        connect.bodyDecoder(),
        oauth.OAuth({
            oauth_provider: new ExampleProvider(),
            request_token_url: '/request_token',
            authorize_url: '/authorize',
            access_token_url: '/access_token',

            authenticate_provider: function(req, resp) {
            },

            authorize_provider: function(req, resp) {
            },

            authorization_finished_provider: function(req, resp) {
            }
        })
    );

    server.listen(TEST_PORT, function() {
        callback(server);
    });
}

module.exports = {
    start_server: start_server,
    CONSUMER_KEY: CONSUMER_KEY,
    CONSUMER_SECRET: CONSUMER_SECRET,
    REQUEST_TOKEN: REQUEST_TOKEN,
    REQUEST_TOKEN_SECRET: REQUEST_TOKEN_SECRET,
    VERIFIER: VERIFIER,
    ACCESS_TOKEN: ACCESS_TOKEN,
    ACCESS_TOKEN_SECRET: ACCESS_TOKEN_SECRET
};
