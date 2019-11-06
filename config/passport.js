const passport = require('passport');
const {
  Strategy: LocalStrategy
} = require('passport-local');
var crypto = require("crypto");
const {
  User
} = require('../db/schema');

const userController = require('../controllers/user');



var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var LinkedInStrategy = require('@sokratis/passport-linkedin-oauth2').Strategy;

passport.use(
  new LocalStrategy({
      usernameField: 'email',
      passwordField: 'password'
    },
    function (email, password, done) {
      userVerification(email, password, done)
    }
  ));


function userVerification(email, password, done) {
  User
    .query()
    .where('email', email)
    .first()
    .then(function (user) {
      if (!user) {
        return done('Unknown user');
      }
      user.verifyPassword(password, function (err, passwordCorrect) {
        if (err) {

          return done(err);
        }
        if (!passwordCorrect) {
          return done('Invalid password');
        }
        return done(null, user)
      })

    }).catch(function (err) {
      console.log(JSON.stringify(err), "random error")
      if (err instanceof Object && !Object.keys(err).length) {
        userVerification(email, password, done)

      } else {
        done(err)


      }
    })

}



passport.use(new GoogleStrategy({
    clientID: "564870927448-d96u97cj6pcfui6l800sbhsbq6ab12kj.apps.googleusercontent.com",
    clientSecret: "uZey9Ql_8WFUlH-uRXpmBtnw",
    callbackURL: "https://sa-auth-dev.dev.jaagalabs.com/auth/google/callback",
    accessType: 'offline',
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
  },
  (accessToken, refreshToken, profile, done) => {
    processSocialLogin(accessToken, refreshToken, profile, done)
  }
));

passport.use(new LinkedInStrategy({
    clientID: "81w4duzaa545xj",
    clientSecret: "wHaoduznJvmGqrhO",
    callbackURL: "https://sa-auth-dev.dev.jaagalabs.com/auth/linkedin/callback",
    scope: ['r_emailaddress', 'r_liteprofile'],
    state: true
  },
  (accessToken, refreshToken, profile, done) => {
    processSocialLogin(accessToken, refreshToken, profile, done)
  }
));



function processSocialLogin(accessToken, refreshToken, profile, done) {
  console.log("profile===", profile);
  if (Array.isArray(profile.emails) && profile.emails[0] && profile.emails[0].value) {
    User
      .query()
      .where('email', profile.emails[0].value)
      .first()
      .then(async function (user) {
        if (!user) {
          console.log('user signing up', profile);
          let photo_url;
          try {
            if (profile.photos && profile.photos[0]) {

              photo_url = {
                key: 'profile.jpg',
                url: profile.photos[0].value
              }
            } else {
              photo_url = {}

            }

            // }
            let userData = {
              email: profile.emails[0].value,
              password: crypto.randomBytes(20).toString('hex'),
              photo_url: JSON.stringify(photo_url),
              name: profile.displayName,
              is_verified: true
            }
            userController.checkIfUserIsInvited(profile.emails[0].value).then(async val => {
              if (val.admin_invited) {
                userData.is_approved = true
              }
              const newUser = await User.query()
                .allowInsert('[email, password, name, photo_url, is_verified]')
                .insert(userData)
                .returning('*').then(val => {
                  console.log(val)
                }).catch(err => {
                  console.log("social signup error===", err)
                });
              return done(null, newUser);

            }).catch(async err => {
              console.log(err)
              processSocialLogin(accessToken, refreshToken, profile, done)



            })



          } catch (err) {
            console.error('user could not be added to db', err);
            return done(err, null);
          }
        } else {
          if (user && !user.photo_url && !user.photo_url['url']) {
            let photo_url;
            if (profile.photos && profile.photos[0]) {

              photo_url = {
                key: 'profile.jpg',
                url: profile.photos[0].value
              }
            } else {
              photo_url = {}
            }

            const updatedUser = await User.query()
              .patchAndFetchById(user.id, {
                photo_url: JSON.stringify(photo_url),
              });
          }
          if (!user.name) {
            const updatedUser = await User.query()
              .patchAndFetchById(user.id, {
                name: profile.displayName
              });
          }
          if (!user.is_verified) {
            const updatedUser = await User.query()
              .patchAndFetchById(user.id, {
                is_verified: true
              });
          }
          return done(null, user);
        }
      }).catch(function (err) {
        console.error(err, 'Error logging in user');
        processSocialLogin(accessToken, refreshToken, profile, done)

        // return done(err, null);
      });
  } else {
    console.error('Did not receive email address', JSON.stringify(profile));
    return done(err, null);
  }
}

module.exports = passport;