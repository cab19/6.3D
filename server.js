const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require("mongoose");
const AutoIncrement = require('mongoose-sequence')(mongoose);
mongoose.connect("mongodb://localhost:27017/iCrowdTask", {useNewUrlParser:true, useUnifiedTopology: true});
const RequesterSchema = require("./models/Requester");
const APIKeys = require("./keys"); // import api keys, file ignored by Git
const crypto = require('crypto'); 
const https = require('https');
const app = express();
const session = require('express-session');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
app.use(cookieParser());

app.use(bodyParser.urlencoded({extended:true}))
app.use(express.static(__dirname + '/public'));

RequesterSchema.plugin(AutoIncrement, {inc_field: 'id'}); // autoincrement id
const Requester = mongoose.model("Requester", RequesterSchema);

// PASSPORT GOOGLE AUTH
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

app.use(session({
    secret : 'd7e208dc921e259b48aade',
    resave: false,
    saveUninitialized: false,
    secure: false,
    //cookie: {maxAge: 10000 }, // low cookie age for testing
    key: 'cookie'
}))
app.use(passport.initialize());
app.use(passport.session());

passport.use('local', Requester.createStrategy()); // local passport strategy

passport.use('google', new GoogleStrategy({ // google passport strategy
    clientID: APIKeys.google.clientID,
    clientSecret: APIKeys.google.clientSecret,
    callbackURL: '/auth/google/callback',
  },
    function(accessToken, refreshToken, profile, done) {    
        // console.log("profile= " + JSON.stringify(profile));
        Requester.findOne({googleId: profile.id}).then((currentUser)=>{ // check if db already has user with same id
            if(currentUser)            
                done(null, currentUser); // use this user, ignore error.
            else{
                //check is email exists, if so add id to it
                Requester.findOne({username: profile.emails[0].value}, (err, foundRequester)=>{  // check if user is in db
                    if (foundRequester){
                        // requester exists in db, so update id

                        Requester.updateOne({username : profile.emails[0].value}, {googleId : profile.id}, (err)=>{
                            if (err)
                                console.log(err);
                            else
                                console.log("Successfully updated!");
                        });
                        
                        done(null, foundRequester); // use existing requester
                    }
                    else{
                        // email not in db, so add new requester
                        let randomPassword = crypto.randomBytes(16).toString('hex'); // random password for account

                        const requester = new Requester({
                            country : "undefined",
                            fName : profile.name.givenName,
                            lName : profile.name.familyName,
                            username : profile.emails[0].value,
                            password : randomPassword,
                            address : "undefined",
                            city : "undefined",
                            state :"undefined",
                            googleId : profile.id
                        }).save().then((requester) =>{
                            done(null, requester); // use the new requester
                        });
                    }
                });
            }
        });
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});
passport.deserializeUser((uid, done) => {
    Requester.findOne({id: uid}, (err, user)=>{
        if (user)
            done(null, user);
    });
});


// ROUTES

app.post('/login',  // default login handler for reqlogin
    passport.authenticate('local', { failureRedirect: '/reqlogin' }),
        function(req, res) { // auth good, determine whether to save credentials and then send to 'homepage'
            if(typeof req.body.rememberMe !== 'undefined'){ // save credentials
                let date = new Date();
                date.setDate(date.getDate() + 7); // add a week, ie save credentials for a week
                req.session.cookie.maxAge = date; // set new expiry
            }
            res.redirect('/reqtask'); // success
        }
);

app.get('/auth/google', passport.authenticate('google', { // route for handling google auth
    scope: [ // the scope, ie the details being returned
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email'
    ]
}));


app.get('/auth/google/callback',  // this is the route google redirects to
    passport.authenticate('google', { failureRedirect: '/reqlogin' }),
        function(req, res) { // auth good, send to 'homepage'
            res.redirect('/reqtask');
});

app.post('/reqregister', (req,res)=>{ // handler for local strategy
    let error = false;
    // ensure passwords match
    let password = req.body.password;
    if(password != req.body.passwordRepeat){
        password = "";
        error = true;
        console.log('Passwords dont match!');
    }
    
    // ensure country is not default option
    let country = req.body.country;
    if(country === "Country of residence *"){
        country = "";
        error = true;
        console.log('Country of residence not entered!');
    }

    if(!error){ // if no errors process form 
        Requester.register({
            username : req.body.username,
            country : req.body.country,
            fName : req.body.fName,
            lName : req.body.lName,
            address : req.body.address,
            city : req.body.city,
            state : req.body.state,
            googleId : "undefined"
        
        }, req.body.password, (err, requester)=>{
            if (err){
                console.log(err)
                res.redirect('/')
            }   
            else{
                //mailchimpSubscribe(req.body.fName, req.body.lName, req.body.username); // send mailchimp email
                passport.authenticate('local', { failureRedirect: '/reqlogin' })
                    (req, res , () => {res.redirect('/')});
            }
        });
    }
});

app.get('/reqtask', (req,res)=>{ // default homepage with authentication check
    if (req.isAuthenticated())
        res.sendFile(__dirname + "/public/reqtask.html");
    else 
        res.redirect('/reqlogin');
});

app.get('/', (req,res)=>{
    res.redirect('/reqtask'); // redirect to homepage, if user not authorised will send them to login
});

app.get('/reqlogin', (req,res)=>{ // requester login page
    res.sendFile(__dirname + "/public/reqlogin.html");
});

app.get('/reqregister', (req,res)=>{ // requester register page
    res.sendFile(__dirname + "/public/reqregister.html");
});

app.get('/forgotpass', (req,res)=>{ // reset password page
    res.sendFile(__dirname + "/public/forgotpass.html");
});

app.post('/resetpass', (req,res)=>{ // reset password handler
    // console.log('req: '+req.body.username);
    Requester.findOne({username: req.body.username}).then((foundRequester)=>{
        if (foundRequester){
            let passtoken = crypto.randomBytes(32).toString('hex');
            Requester.updateOne({username : req.body.username}, {passwordResetToken : passtoken}, (err)=>{
                if (err)
                    console.log(err);
                else{
                    //console.log("Token updated!");
                    const mailTransport = nodemailer.createTransport({
                        host: 'smtp.mail.yahoo.com',
                        port: 465,
                        service:'yahoo',
                        secure: false,
                        auth: {
                           user: APIKeys.yahoo.username,
                           pass: APIKeys.yahoo.password
                        },
                    });

                    const mailOptions = {
                        from: 'icrowdtask@yahoo.com',
                        to: req.body.username,
                        subject: 'iCrowdTask - Reset Password Request',
                        text:
                        'A request was recently received from your account to reset your password.\n\n'+
                        'Please use the link below to reset your password, or ignore if you didn\'t make this request.\n\n'+
                        'http://node.com:8080/reset/?passtoken='+passtoken // CHANGE Heroku
                    };

                    // console.log('Attempt send mail');

                    mailTransport.sendMail(mailOptions, (err, res) =>{
                        if(err)
                            console.log('Mail error: '+err);
                    });
                }
            });
        }
        else{
            console.log("Ignoring password reset request");
        }
    });
    res.redirect('/reqlogin');
});

app.get('/reset', (req,res)=>{ // reset password handler
    Requester.findOne({passwordResetToken: req.query.passtoken}).then((foundRequester)=>{
        if (foundRequester){ // token matches
            // authenticate user and redirect to update password page
            req.login(foundRequester, (err)=>{
                if(err) 
                    console.log('Issue logging in');
                else{
                    //console.log('redirect to update password');
                    res.redirect('/updatepass');
                }
            });
        }
        else
            console.log('Ignoring request.');
    });
});

app.get('/updatepass', (req,res)=>{ // update password page with authentication check
    if (req.isAuthenticated())
        res.sendFile(__dirname + "/public/updatepass.html");
    else 
        res.redirect('/reqlogin');
});

app.post('/updatepass', (req,res)=>{ // update password handler with authentication check
    if (req.isAuthenticated()){
        console.log('process password UPDATE');
        if(req.body.password){ // make sure theres a password
            //console.log(JSON.stringify(req.user));
            Requester.findOne({username: req.user.username}, (err, foundRequester)=>{        
                if (!foundRequester)
                    res.send('No result found');
                else
                {
                    foundRequester.setPassword(req.body.password, function(){ // use set password to overwrite password
                        foundRequester.save(); // update password.
                        console.log('Password Successfully updated.');
                        res.redirect('/');
                    });             
                }
            });
        }
    }
});

// ROUTES END

// REST API ROUTES

app.route('/requesters')
.get((req, res)=>{ // return all requesters
    Requester.find((err, requesterList)=>{
        if (err)
            res.send(err);
        else 
            res.send(requesterList);
    });
})
.post((req,res)=>{ // add a requester
    Requester.register({
        username : req.body.username,
        country : req.body.country,
        fName : req.body.fName,
        lName : req.body.lName,
        address : req.body.address,
        city : req.body.city,
        state : req.body.state,
        googleId : "undefined"
    
    }, req.body.password, (err, requester)=>{
        if (err)
            res.send(err);
        else
            res.send ('Successfully added a new requester!');
    });
})
.delete((req,res) =>{ // delete all requesters and reset id counter
    Requester.deleteMany((err) =>{
        if (err)
            res.send(err);
        else{
            Requester.counterReset('id', function(err) {
                // Now the counter is 0
            });
            res.send('Successfully deleted all requesters!');
        }
    });
})

app.route('/requesters/:id')
.get((req, res)=>{ // retrieve single requester
    Requester.findOne({id: req.params.id}, (err, foundRequester)=>{        
        if (!foundRequester)
            res.send('No result found');
        else
            res.send(foundRequester);
    });
})
.patch((req, res)=>{ //update single requester
    //console.log(JSON.stringify(req.body));
    Requester.findOne({id: req.params.id}, (err, foundRequester)=>{
    if(req.body.oldpassword){ // password change requested, update using local strategy
        Requester.findOne({id: req.params.id}, (err, foundRequester)=>{        
            if (!foundRequester)
                res.send('No result found');
            else
            {
                foundRequester.changePassword(req.body.oldpassword, req.body.newpassword, (err)=>{
                    if(err)
                        res.send(err);
                    else
                        res.send('Password Successfully updated.');
                });                
            }
        });
    }
    else{
        Requester.update(
            {id: req.params.id},
            {$set: req.body},
            (err)=>{
                if (err)
                    res.send(err);
                else
                    res.send('Record Successfully updated.');
            }
        );
    }
    })
})
.delete((req,res) =>{ // delete single requester
    Requester.deleteOne(
        {id: req.params.id},
        (err)=>{
            if (err)
                res.send(err);
            else
                res.send('Successfully deleted requester '+req.params.id+'!');
        }
    );
});    

// API END


function mailchimpSubscribe(fName, lName, email){
    const data = {
        members:[{
            email_address: email,
            status : "subscribed",
            merge_fields:{
                FNAME: fName,
                LNAME:lName,
            },
        }]
    };
    jsonData = JSON.stringify(data);
    
    const listId = "88efab0acc";
    const url = "https://us17.api.mailchimp.com/3.0/lists/"+listId;
    const options={
        method: "POST",
        auth:"cb:"+APIKeys.mailChimpAPIKey,
    };

    const request = https.request(url, options , (response)=>{
        response.on("data", (data)=> {/*console.log(JSON.parse(data)) */});
    });

    request.write(jsonData);
    request.end();
    //console.log("MAILCHIMP "+fName,lName,email);
}

app.listen(8080, function (request, response){
    console.log("Server is running on 8080");
})