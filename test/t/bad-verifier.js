// Test for failure if the verifier is not returned correctly...
//


var CONSUMER_KEY = 'dpf43f3p2l4k3l03',
    CONSUMER_SECRET = 'kd94hf93k423kf44',

    assert = require('assert'),
    test_request = require('request').test_request,
    oauth_request = require('request').oauth_request,
    qsparse = require('querystring').parse,
    start_server = require('example').start_server;


start_server(function(server) {
    // Test a PLAINTEXT request...
    oauth_request({
        parameters: [
            ['oauth_consumer_key', CONSUMER_KEY],
            ['oauth_callback','http://printer.example.com/request_token_ready']
        ],
        accessor: {
            consumerSecret: CONSUMER_SECRET,
        },
        action: 'http://photos.example.com/request_token',
        method: 'GET'
        }, function(resp, body) {
            var req_token = qsparse(body);

            // Authorize the token...
            test_request('POST', '/authorize', 
                {'Content-Type': 'application/x-www-form-urlencoded'},
                'username=jane&password=mypassword&oauth_token='+req_token.oauth_token,
                function(resp, body) {
                    // Exchange for an access token...
                    oauth_request({
                        parameters: [
                            ['oauth_consumer_key', CONSUMER_KEY],
                            ['oauth_token', 'hh5s93j4hdidpola'],
                            ['oauth_verifier', 'baadf00d']
                            ],
                        accessor: {
                            consumerSecret: CONSUMER_SECRET,
                            tokenSecret: req_token.oauth_token_secret
                        },
                        action: 'http://photos.example.com/access_token',
                        method: 'GET'
                        }, function(resp, body) {
                            // Request should fail...
                            assert.equal(resp.statusCode, 400);
                            server.close();
                    });
            });

    });
});
