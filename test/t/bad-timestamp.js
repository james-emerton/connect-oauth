// Test for failure if the verifier is not returned correctly...
//


var assert = require('assert'),
    test_request = require('request').test_request,
    oauth_request = require('request').oauth_request,
    qsparse = require('querystring').parse,
    example = require('example');


example.start_server(function(server) {
    // Second request should fail...
    var accessed = false;
    server.use('/test', function(req, resp) {
        if(!accessed) {
            resp.writeHead(200, {'Content-Type': 'text/plain'});
            resp.end('OK');
            accessed = true;
        }
        else
            assert.fail("Timestamp validation failure");
    });

    oauth_request({
        parameters: [
            ['oauth_consumer_key', example.CONSUMER_KEY],
            ['oauth_token', example.ACCESS_TOKEN],
        ],
        accessor: {
            consumerSecret: example.CONSUMER_SECRET,
            tokenSecret: example.ACCESS_TOKEN_SECRET
        },
        action: 'http://photos.example.com/test',
        method: 'GET'
        }, function(resp, body) {
            oauth_request({
                parameters: [
                    ['oauth_consumer_key', example.CONSUMER_KEY],
                    ['oauth_token', example.ACCESS_TOKEN],
                    ['oauth_timestamp', 10000]
                ],
                accessor: {
                    consumerSecret: example.CONSUMER_SECRET,
                    tokenSecret: example.ACCESS_TOKEN_SECRET
                },
                action: 'http://photos.example.com/test',
                method: 'GET'
                }, function(resp, body) {
                    assert.equal(resp.statusCode, 401);
                    server.close();
            });
    });
});
