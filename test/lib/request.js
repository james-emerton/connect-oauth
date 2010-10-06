var TEST_PORT = parseInt(process.env['TEST_PORT']),
    http = require('http'),
    url = require('url'),
    OAuthClient = require('oauth-client');

function test_request(method, uri, headers, data, callback) {
    var client = http.createClient(TEST_PORT, '127.0.0.1'),
        request = client.request(method, uri, headers);

    if(data)
        request.write(data);

    request.end();
    request.on('response', function(resp) {
        var body = '';
        resp.setEncoding('utf8');
        resp.on('data', function(chunk) {
            body += chunk;
        });

        resp.on('end', function() {
            callback(resp, body);
        });
    });
}

function oauth_request(msg, callback) {
    OAuthClient.completeRequest(msg, msg.accessor);

    var urlobj = url.parse(msg.action, true),
        newurl = { pathname: urlobj.pathname },
        use_auth_header = msg.auth_header || false;

    if(msg.method == 'GET' && !use_auth_header)
        newurl.query = OAuthClient.getParameterMap(msg.parameters);

    test_request(msg.method, url.format(newurl),
        {'Host': urlobj.hostname}, null, callback);
}

module.exports = {
    test_request: test_request,
    oauth_request: oauth_request
}
