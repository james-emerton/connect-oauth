[
  'oauth', 'oauth_error', 'oauth_services'
].forEach(function(path){
	var module = require('./' + path);
	for (var i in module)
		exports[i] = module[i];
});
