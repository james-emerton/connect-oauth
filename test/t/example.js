//
// Run the OAuth Example code as in Appendix A of the spec...


var CONSUMER_KEY = 'dpf43f3p2l4k3l03',
    CONSUMER_SECRET = 'kd94hf93k423kf44',

    assert = require('assert'),
    url = require('url'),
    test_request = require('request').test_request,
    oauth_request = require('request').oauth_request,
    qsparse = require('querystring').parse,
    example = require('example');


example.start_server(function(server) {
    // Test a PLAINTEXT request...
    oauth_request({
        parameters: [
            ['oauth_consumer_key', example.CONSUMER_KEY],
            ['oauth_signature_method', 'PLAINTEXT'],
            ['oauth_callback','http://printer.example.com/request_token_ready']
        ],
        accessor: {
            consumerSecret: example.CONSUMER_SECRET,
        },
        action: 'http://photos.example.com/request_token',
        method: 'GET'
        }, function(resp, body) {
            assert.equal(resp.headers['content-type'],
                'application/x-www-form-urlencoded');

            var result = qsparse(body);
            assert.equal(result.oauth_token, example.REQUEST_TOKEN);
            assert.equal(result.oauth_token_secret, example.REQUEST_TOKEN_SECRET);
            assert.equal(result.oauth_callback_confirmed, 'true');

            var req_token_secret = result.oauth_token_secret;

            // Authorize the token...
            test_request('POST', '/authorize', 
                {'Content-Type': 'application/x-www-form-urlencoded'},
                'username=jane&password=mypassword&oauth_token='+result.oauth_token,
                function(resp, body) {
                    // We should be getting a redirect to our callback...
                    assert.equal(resp.statusCode, 307);
                    var redir = url.parse(resp.headers.location, true);
                    assert.equal(redir.host, 'printer.example.com');
                    assert.equal(redir.pathname, '/request_token_ready');
                    assert.equal(redir.query.oauth_token, example.REQUEST_TOKEN);
                    assert.equal(redir.query.oauth_verifier, example.VERIFIER);

                    // Exchange for an access token...
                    oauth_request({
                        parameters: [
                            ['oauth_consumer_key', example.CONSUMER_KEY],
                            ['oauth_token', example.REQUEST_TOKEN],
                            ['oauth_signature_method', 'PLAINTEXT'],
                            ['oauth_verifier',redir.query.oauth_verifier]
                            ],
                        accessor: {
                            consumerSecret: example.CONSUMER_SECRET,
                            tokenSecret: req_token_secret
                        },
                        action: 'http://photos.example.com/access_token',
                        method: 'GET'
                        }, function(resp, body) {
                            assert.equal(resp.statusCode, 200);
                            assert.equal(resp.headers['content-type'],
                                'application/x-www-form-urlencoded');
                            var args = qsparse(body);
                            assert.equal(args.oauth_token, example.ACCESS_TOKEN);
                            assert.equal(args.oauth_token_secret,
                                example.ACCESS_TOKEN_SECRET);

                            server.close();
                    });
            });

    });
});
