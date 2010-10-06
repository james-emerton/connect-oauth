//
// Run the OAuth Example code as in Appendix A of the spec...


var CONSUMER_KEY = 'dpf43f3p2l4k3l03',
    CONSUMER_SECRET = 'kd94hf93k423kf44',

    assert = require('assert'),
    url = require('url'),
    test_request = require('request').test_request,
    oauth_request = require('request').oauth_request,
    qsparse = require('querystring').parse,
    start_server = require('example').start_server;


start_server(function(server) {
    // Test a PLAINTEXT request...
    oauth_request({
        parameters: [
            ['oauth_consumer_key', CONSUMER_KEY],
            ['oauth_signature_method', 'PLAINTEXT'],
            ['oauth_callback','http://printer.example.com/request_token_ready']
        ],
        accessor: {
            consumerSecret: CONSUMER_SECRET,
        },
        action: 'http://photos.example.com/request_token',
        method: 'GET'
        }, function(resp, body) {
            assert.equal(resp.headers['content-type'],
                'application/x-www-form-urlencoded');

            var result = qsparse(body);
            assert.equal(result.oauth_token, 'hh5s93j4hdidpola');
            assert.equal(result.oauth_token_secret, 'hdhd0244k9j7ao03');
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
                    assert.equal(redir.query.oauth_token, 'hh5s93j4hdidpola');
                    assert.equal(redir.query.oauth_verifier, 'hfdp7dh39dks9884');

                    // Exchange for an access token...
                    oauth_request({
                        parameters: [
                            ['oauth_consumer_key', CONSUMER_KEY],
                            ['oauth_token', 'hh5s93j4hdidpola'],
                            ['oauth_signature_method', 'PLAINTEXT'],
                            ['oauth_verifier',redir.query.oauth_verifier]
                            ],
                        accessor: {
                            consumerSecret: CONSUMER_SECRET,
                            tokenSecret: req_token_secret
                        },
                        action: 'http://photos.example.com/access_token',
                        method: 'GET'
                        }, function(resp, body) {
                            assert.equal(resp.statusCode, 200);
                            assert.equal(resp.headers['content-type'],
                                'application/x-www-form-urlencoded');
                            var args = qsparse(body);
                            assert.equal(args.oauth_token, 'nnch734d00sl2jdk');
                            assert.equal(args.oauth_token_secret, 'pfkkdhi9sl3r4s00');

                            server.close();
                    });
            });

    });
});
