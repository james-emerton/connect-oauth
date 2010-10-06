// Run tests...
//

var exec = require('child_process').exec,
    sys = require('sys'),
    path = require('path'),
    node = process.execPath,
    dir = path.dirname(process.argv[1]),
    test_dir = path.join(dir, 't'),
    tests = require('fs').readdirSync(test_dir)
            .filter(function(t) {return /\.js$/.test(t)})
            .map(function(t) {return path.join(test_dir, t)});


function run_tests(queue) {
    var test = queue.shift();

    sys.print("Running "+path.basename(test)+" ... ");

    exec(node+' '+test, {
        timeout: 5000,
        env: {
            TEST_PORT: '8088',
            NODE_PATH: path.join(dir, 'lib')
                        +":"+path.join(dir, '../lib')
        }
    }, function(error, stdout, stderr) {
        if(error) {
            sys.print("FAIL!\n");
            sys.print(error.message);
        }
        else
            sys.print("OK\n");

        // Continue testing...
        if(queue.length)
            run_tests(queue);
    });
}

run_tests(tests);
