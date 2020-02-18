/**
 * Module dependencies.
 */

const express = require('express');
var session = require('express-session');
const bodyParser = require('body-parser');
const chalk = require('chalk');
const dotenv = require('dotenv');
const passport = require('passport');
const expressValidator = require('express-validator');

/**
 * Load environment variables from .env file, where API keys and passwords are configured.
 */
dotenv.load({
  path: '.env'
});

if (!process.env.ENCRYPTION_KEY) {
  throw new Error('JWT encryption key required')
}

/**
 * Controllers (route handlers).
 */
const userController = require('./controllers/user');

/**
 * Create Express server.
 */
const app = express();

/**
 * Express configuration.
 */
app.set('host', '0.0.0.0');
app.set('port', process.env.PORT || 8080);
app.set('json spaces', 2); // number of spaces for indentation
app.use(bodyParser.json());
app.use(expressValidator());
// required for passport
app.use(session({ secret: 'socialalpha', resave: false, saveUninitialized: true, })); // session secret
app.use(passport.initialize());
app.use(passport.session());
app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  next();
});
app.post('/auth/login', userController.postLogin);
app.post('/auth/signup', userController.postSignup);
// app.get('/auth/verify', userController.completeVerification);
app.post('/auth/verify', userController.completeVerification);
app.post('/auth/verification', userController.getVerificationCode);
app.post('/auth/changepassword', userController.postPasswordChange);
app.post('/auth/passwordreset', userController.getPasswordResetCode);
app.get('/auth/google',
  // Save the url of the user's current page so the app can redirect back to
  // it after authorization
  (req, res, next) => {
    if (req.query.return) {
      req.session.oauth2return = req.query.return;
    }
    next();
  },
  // Start OAuth 2 flow using Passport.js
  passport.authenticate('google', {
    session: false,
    scope: ['email', 'profile']
  })
);
app.get('/auth/google/callback', userController.postGoogleLogin);
app.get('/auth/linkedin',
  // Start OAuth 2 flow using Passport.js
  passport.authenticate('linkedin'),
  function(req, res){
    // The request will be redirected to LinkedIn for authentication, so this
    // function will not be called.
  }
);
app.get('/auth/linkedin/callback', userController.postLinkedinLogin);
/**
 * Start Express server.
 */
app.listen(app.get('port'), () => {
  console.log('%s App is running at http://%s:%d in %s mode', chalk.green('✓'), app.get('host'), app.get('port'), app.get('env'));
  console.log('  Press CTRL-C to stop\n');
});

module.exports = app;