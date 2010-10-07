// Test for failure if the verifier is not returned correctly...
//


var assert = require('assert'),
    test_request = require('request').test_request,
    oauth_request = require('request').oauth_request,
    qsparse = require('querystring').parse,
    example = require('example');


example.start_server(function(server) {
    // Add a protected resource...
    server.use('/test', function(req, resp) {
        assert.fail("Signature validation false positive");
    });

    oauth_request({
        parameters: [
            ['oauth_consumer_key', example.CONSUMER_KEY],
            ['oauth_token', example.ACCESS_TOKEN],
        ],
        accessor: {
            consumerSecret: 'wrong',
            tokenSecret: 'alsowrong'
        },
        action: 'http://photos.example.com/test',
        method: 'GET'
        }, function(resp, body) {
            assert.equal(resp.statusCode, 401);
            assert.equal(resp.headers['www-authenticate'],
                'OAuth realm="http://photos.example.net/"');
            server.close();
    });
});
