const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

//Create local strategy
const localOptions = { usernameField: 'email'};
const localLogin = new LocalStrategy(localOptions, function(email, password, done){
  //Verify this email and password, call done with the user
  // It it is the correct email and password
  //otherwise, call sone with false
  User.findOne({ email: email }, function(err, user){
    if(err){ return done(err)}
    if(!user){ return done(null, false); }

    //compare passwords - is 'password' equal to usr.password?
    user.comparePassword(password, function(err, isMatch){
      if(err) { return done(err); }
      if(!isMatch) { return done(null, false); }

      return done(null, user);
    });
  });
});

// Setup options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

//Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
  //See if the user ID in the payload exist in our database, if so call done
  //with that user, otherwise, call done without user
  User.findById(payload.sub, function(err, user){
    if(err) { return done(err, false); }

    if(user){
      done(null, user);
    }else{
      done(null, false);
    }
  });
});

//Tell Passport to use this stategy
passport.use(jwtLogin);
passport.use(localLogin);
