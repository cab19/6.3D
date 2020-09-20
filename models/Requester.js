const mongoose = require("mongoose");
const validator = require("validator");
const AutoIncrement = require('mongoose-sequence')(mongoose);
const passportLocalMongoose = require ('passport-local-mongoose');

const requesterSchema = new mongoose.Schema({
    username:  String,
    country:{
        type: String, 
        //required:true
    },
    fName:{
        type: String, 
        //required:true,        
    },
    lName:{
        type: String,
        //required:true,        
    },
    username:{
        type: String,
        //lowercase:true,
       // required:true,
        validate(value){
            if (!validator.isEmail(value))
                throw new Error('The email is not valid!');
        }        
    },
    password:{
        type: String, 
        minlength:8,
        //required:true,        
    },
    address:{
        type: String, 
        //required:true,        
    },
    city:{
        type: String,
        //required:true,        
    },
    state:{
        type: String, 
        //required:true,        
    },
    postCode:{
        type: Number
    },
    mobileNumber:{
        type: String,
        validate(value){
            if(value){
                if (!validator.isMobilePhone(value, 'en-AU'))
                    throw new Error('The mobile number is not valid!');
            }
        }               
    },
    googleId:{
        type: String,
    },
    passwordResetToken:{
        type: String,
    },
});

requesterSchema.plugin(passportLocalMongoose);

//module.exports  =  requesterSchema;

// const requesterSchema = new mongoose.Schema(
//     {
        
//         username:  String,
//         password: String
//     }
// )
// requesterSchema.plugin(passportLocalMongoose);

module.exports  =  requesterSchema;