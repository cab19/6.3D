const bcrypt = require('bcrypt-nodejs');

module.exports = {
    hash : function(password, callback){
        bcrypt.genSalt(10, function (err, salt) {
            if (!err) {
                bcrypt.hash(password, salt, null, function (err, hash) {
                    if (!err)
                        callback(hash);                                
                });
            }
        });
    }
};