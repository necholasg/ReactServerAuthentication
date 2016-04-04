const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user){
  const timeStamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timeStamp }, config.secret)
}

module.exports.signin = function(req, res, next){
  //User has already had thier email and password auth'd
  //We just need to give them a token
  res.json({ token: tokenForUser(req.user) });
}

module.exports.signup = function(req, res, next){
  const email = req.body.email;
  const password = req.body.password;

  if(!email || !password){
    return res.status(422).send({ error: "You must provide email and password"});
  }
  //see if a user with teh given email exists
  User.findOne({ email: email }, function(err, existingUser){
    if(err){ return next(err); }

    //if a user with email does exist, return an error
    if(existingUser){
      return res.status(422).send({ error: 'Email is in use'});
    }
    //If a user with email does not exist, create and save user record
    const user = new User({
      email: email,
      password: password
    });

    user.save(function(err){
      if(err){ return next(err); }
      // Respond to request indicating the user was created
      res.json({ token: tokenForUser(user)});
      });
  });
};
