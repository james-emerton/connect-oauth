
var assert = require('assert'),
    url = require('url'),
    test_request = require('request').test_request,
    oauth_request = require('request').oauth_request,
    qsparse = require('querystring').parse,
    example = require('example');

example.start_server(function(server) {
    // Add a protected resource...
    server.use('/test', function(req, resp) {
        resp.writeHead(200, {'Content-Type': 'text/plain'});
        resp.end('Protected stuff!');
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
        assert.equal(resp.statusCode, 200);
        assert.equal(body, 'Protected stuff!');

        server.close();
    });
});
