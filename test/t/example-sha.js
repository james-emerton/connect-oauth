
var CONSUMER_KEY = 'dpf43f3p2l4k3l03',
    CONSUMER_SECRET = 'kd94hf93k423kf44',

    assert = require('assert'),
    test_request = require('request').test_request,
    oauth_request = require('request').oauth_request,
    OAuthClient = require('oauth-client'),
    start_server = require('example').start_server;

start_server(function test_sha1(server) {
    // Test HMAC-SHA1 signature...
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
            assert.equal(resp.headers['content-type'],
                'application/x-www-form-urlencoded');

            var result = OAuthClient.getParameterMap(OAuthClient.decodeForm(body));
            assert.equal(result.oauth_token, 'hh5s93j4hdidpola');
            assert.equal(result.oauth_token_secret, 'hdhd0244k9j7ao03');
            assert.equal(result.oauth_callback_confirmed, 'true');

        server.close();
    });
});
