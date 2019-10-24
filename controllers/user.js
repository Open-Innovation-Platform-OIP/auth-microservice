const {
  promisify
} = require("util");
const passport = require("../config/passport");
const {
  User
} = require("../db/schema");
const {
  InvitedUsers
} = require("../db/invited_users_schema");
const {
  errorHandler
} = require("../db/errors");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const randomBytesAsync = promisify(crypto.randomBytes);

const transporter = nodemailer.createTransport({
  // port: 587,
  service: "gmail",
  auth: {
    user: "mail@jaaga.in",
    pass: "mail@jaaga"
  },
  tls: {
    rejectUnauthorised: false
  }
});

async function sendMail(req) {
  var mailOptions = {
    from: "mail@jaaga.in",
    to: req.to,
    subject: req.subject,
    text: req.text
  };

  return new Promise((resolve, reject) => {
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        // console.log(error);
        reject(error.response);
      } else {
        // console.log('Email sent: ' + info.response);
        resolve(info.response);
      }
    });
  });
}

function generateOTP() {
  // Declare a digits variable
  // which stores all digits
  var digits = "0123456789";
  let OTP = "";
  for (let i = 0; i < 4; i++) {
    OTP += digits[Math.floor(Math.random() * 10)];
  }
  return OTP;
}

async function sendVerificationCode(req, res) {
  try {
    User.query()
      .where("email", req.body.email)
      .first()
      .then(async function (user) {
        if (!user) {
          return res.status(500).send({
            msg: "User is not found"
          });
        }
        if (user.is_verified) {
          return res.status(500).send({
            msg: "User is already verified"
          });
        }
        const otp = generateOTP();
        await User.query().patchAndFetchById(user.id, {
          otp: otp
        });
        const mail = {
          to: user.email,
          subject: "Social Alpha Account Verification",
          text: "Hello,\n\n" +
            "Please use the following OTP to change your password: " +
            otp +
            ".\n"
          // text: 'Hello,\n\n' + 'Please verify your account by clicking the link: \nhttp:\/\/' + 'social-alpha-open-innovation.firebaseapp.com' + '\/auth\/verify\/?email=' + user.email + '&otp=' + otp + '.\n'
        };
        const response = await sendMail(mail);
        const msg = {
          msg: "A verification email has been sent to " + user.email + "."
        };
        res.status(200).send(msg);
      })
      .catch(function (err) {
        return res.status(500).send({
          msg: err.message
        });
      });
  } catch (err) {
    errorHandler(err, res);
    return;
  }
}

async function sendPasswordResetCode(req, res) {
  try {
    User.query()
      .where("email", req.body.email)
      .first()
      .then(async function (user) {
        if (!user) {
          return res.status(500).send({
            msg: "User not found"
          });
        }
        const otp = generateOTP();
        // console.log(user, otp);
        await User.query().patchAndFetchById(user.id, {
          otp: otp
        });
        const mail = {
          to: user.email,
          subject: "Social Alpha - Password Reset",
          text: "Hello,\n\n" +
            "Please use the following OTP to change your password: " +
            otp +
            ".\n"
        };
        const response = await sendMail(mail);
        const msg = {
          msg: "A password reset email has been sent to " + user.email + "."
        };
        res.status(200).send(msg);
      })
      .catch(function (err) {
        return res.status(500).send({
          msg: err.message
        });
      });
  } catch (err) {
    errorHandler(err, res);
    return;
  }
}



/**
 * Sign in with Google
 */
exports.postGoogleLogin = async (req, res, next) => {
  let role = "user";

  passport.authenticate("google", (err, user) => {
    // console.log(err, user);
    if (err) {
      res.writeHead(302, {
        'Location': 'https://oip-dev.dev.jaagalabs.com/auth/login?err=' + err
      });
      res.end();
    }
    if (user) {
      if (user.is_admin) {
        role = "admin";
      }

      // console.log(user, "user");

      if (!user.is_approved) {
        // console.log(user, "user");
        let error = "User is not approved";
        console.log("test");

        res.writeHead(302, {
          Location: "https://oip-dev.dev.jaagalabs.com/auth/login?err=" + error
        });
        res.end();
      }

      console.log(JSON.stringify(user));
      const tokenContents = {
        sub: "" + user.id,
        name: user.email,
        iat: Date.now() / 1000,
        "https://hasura.io/jwt/claims": {
          "x-hasura-allowed-roles": ["editor", "user", "mod", "admin"],
          "x-hasura-user-id": "" + user.id,
          "x-hasura-default-role": role,
          "x-hasura-role": role
        }
      };
      const token = jwt.sign(tokenContents, process.env.ENCRYPTION_KEY);
      res.writeHead(302, {
        Location: "https://oip-dev.dev.jaagalabs.com/auth/login?token=" +
          token +
          "&email=" +
          user.email +
          "&id=" +
          user.id +
          "&role=" +
          role
      });
      res.end();
    }
  })(req, res, next);
};

/**
 * Sign in with LinkedIn
 */
exports.postLinkedinLogin = async (req, res, next) => {
  let role = "user";

  passport.authenticate("linkedin", (err, user) => {
    // console.log(err, user);
    if (err) {
      res.writeHead(302, {
        'Location': 'https://oip-dev.dev.jaagalabs.com/auth/login?err=' + err
      });
      res.end();
    }
    if (user) {
      if (user.is_admin) {
        role = "admin";
      }

      console.log(user, "user");

      if (!user.is_approved) {
        console.log(user, "user");
        let error = "User is not approved";

        res.writeHead(302, {
          Location: "https://oip-dev.dev.jaagalabs.com/auth/login?err=" + error
        });
        res.end();
      }
      console.log(JSON.stringify(user));
      const tokenContents = {
        sub: "" + user.id,
        name: user.email,
        iat: Date.now() / 1000,
        "https://hasura.io/jwt/claims": {
          "x-hasura-allowed-roles": ["editor", "user", "mod", "admin"],
          "x-hasura-user-id": "" + user.id,
          "x-hasura-default-role": role,
          "x-hasura-role": role
        }
      };
      const token = jwt.sign(tokenContents, process.env.ENCRYPTION_KEY);
      res.writeHead(302, {
        Location: "https://oip-dev.dev.jaagalabs.com/auth/login?token=" +
          token +
          "&email=" +
          user.email +
          "&id=" +
          user.id +
          "&role=" +
          role
      });
      res.end();
    }
  })(req, res, next);
};

function checkIfUserIsInvited(email) {

  const userIsInvited = InvitedUsers
    .query()
    .where('email', email)
    .first()
    .then(function (user) {
      if (!user) {
        return false;
      } else {
        // console.log("User exists", user)

        return true;
      }

    }).catch(function (err) {
      console.log(JSON.stringify(err), "random error")
      return false

    });

  return userIsInvited;

}

/**
 * POST /login
 * Sign in using email and password.
 */
exports.postLogin = async (req, res, next) => {
  let role = "user";
  req.assert("email", "Email cannot by empty").notEmpty();
  req.assert("email", "Email is not valid").isEmail();
  req.assert("password", "Password cannot be blank").notEmpty();
  req.sanitize("email").normalizeEmail({
    gmail_remove_dots: false
  });
  const errors = req.validationErrors();

  // queryTest("vishnu@jaaga.in");




  if (errors) {
    return res.status(400).json({
      errors: errors,
      test: "test"
    });
  }


  passport.authenticate("local", (err, user) => {
    if (err) {
      return handleResponse(res, 400, {
        msg: err
      });
    }
    if (!user.is_verified) {
      return handleResponse(res, 401, {
        type: "not-verified",
        msg: "Your account has not been verified."
      });
    }
    console.log(user, "user 2");
    if (!user.is_approved) {
      console.log(user, "user");

      return handleResponse(res, 401, {
        type: "not-approved",
        msg: "Your account has not been approved by an admin."
      });
    }
    if (user) {
      if (user.is_admin) {
        role = "admin";
      }
      const tokenContents = {
        sub: "" + user.id,
        name: user.email,
        iat: Date.now() / 1000,
        "https://hasura.io/jwt/claims": {
          "x-hasura-allowed-roles": ["editor", "user", "mod", "admin"],
          "x-hasura-user-id": "" + user.id,
          "x-hasura-default-role": role,
          "x-hasura-role": role
        }
      };
      // const token = jwt.sign(tokenContents, process.env.ENCRYPTION_KEY);
      // res.writeHead(302, {
      // 	'Location': 'http://localhost:4200/login?token=' + token + '&user=' + user.email + '&id=' + user.id
      // });
      // res.end();

      handleResponse(res, 200, {
        token: jwt.sign(tokenContents, process.env.ENCRYPTION_KEY),
        id: user.id,
        is_verified: user.is_verified,
        role: role,
        is_admin: user.is_admin
      });
    }
  })(req, res, next);
};

/**
 * POST /signup
 * Create a new local account.
 */
exports.postSignup = async (req, res, next) => {
  req.assert("name", "Name cannot be empty").notEmpty();
  req.assert("email", "Email cannot be empty").notEmpty();
  req.assert("email", "Email is not valid").isEmail();
  req.assert("password", "Password must be at least 4 characters long").len(4);
  req
    .assert("confirmPassword", "Passwords do not match")
    .equals(req.body.password);
  req.sanitize("email").normalizeEmail({
    gmail_remove_dots: false
  });
  const errors = req.validationErrors();

  if (errors) {
    return res.status(400).json({
      errors: errors
    });
  }

  try {
    await User.query()
      .allowInsert("[email, password, name]")
      .insert({
        email: req.body.email,
        password: req.body.password,
        name: req.body.name,
        photo_url: {}
      });
  } catch (err) {
    errorHandler(err, res);
    return;
  }

  const userIsInvited = checkIfUserIsInvited(req.body.email);
  console.log(userIsInvited, "user is invited");
  // Send the verification email
  sendVerificationCode(req, res);
};

/**
 * POST /verification
 * Create a new local account.
 */
exports.getPasswordResetCode = async (req, res, next) => {
  req.assert("email", "Email cannot by empty").notEmpty();
  req.assert("email", "Email is not valid").isEmail();
  req.sanitize("email").normalizeEmail({
    gmail_remove_dots: false
  });
  const errors = req.validationErrors();

  if (errors) {
    return res.status(400).json({
      errors: errors
    });
  }
  // Send the verification email
  sendPasswordResetCode(req, res);
};

/**
 * POST /changepassword
 * Create a new password
 */
exports.postPasswordChange = async (req, res, next) => {
  req.assert("email", "Email cannot by empty").notEmpty();
  req.assert("email", "Email is not valid").isEmail();
  req.assert("otp", "OTP cannot be empty").notEmpty();
  req.assert("password", "Password must be at least 4 characters long").len(4);
  req
    .assert("confirmPassword", "Passwords do not match")
    .equals(req.body.password);
  req.sanitize("email").normalizeEmail({
    gmail_remove_dots: false
  });
  const errors = req.validationErrors();

  if (errors) {
    return res.status(400).json({
      errors: errors
    });
  }
  try {
    User.query()
      .where("email", req.body.email)
      .where("otp", req.body.otp)
      .first()
      .then(async function (user) {
        // console.log(user);
        if (!user) {
          return res.status(500).send({
            msg: "User not found"
          });
        }
        // if (!user.token === req.query.token) {
        //   return res.status(500).send({
        //     msg: "Invalid or expired token."
        //   });
        // }
        // user.is_verified = true;
        try {
          const salt = bcrypt.genSaltSync();
          const password = await bcrypt.hash(req.body.password, salt);
          // const createRandomToken = await randomBytesAsync(16).then(buf => buf.toString('hex'));
          // token = createRandomToken;
          const updatedUser = await User.query().patchAndFetchById(user.id, {
            password: password,
            otp: null
            // token: createRandomToken
          });
          console.log("id: ", updatedUser.id, updatedUser.email);
          const msg = {
            msg: "Password has been updated for user with email " +
              user.email +
              "."
          };
          res.status(200).send(msg);
        } catch (err) {
          errorHandler(err, res);
          return;
        }
      })
      .catch(function (err) {
        return res.status(500).send({
          msg: err.message
        });
      });
  } catch (err) {
    errorHandler(err, res);
    return;
  }
};

/**
 * POST /verification
 * Create a email verification request.
 */
exports.getVerificationCode = async (req, res, next) => {
  req.assert("email", "Email cannot by empty").notEmpty();
  req.assert("email", "Email is not valid").isEmail();
  req.sanitize("email").normalizeEmail({
    gmail_remove_dots: false
  });
  const errors = req.validationErrors();

  if (errors) {
    return res.status(400).json({
      errors: errors
    });
  }
  // Send the verification email
  sendVerificationCode(req, res);
};

/**
 * GET /verify
 * Verify user's email
 */

exports.completeVerification = async (req, res, next) => {
  req.assert("email", "Email cannot be empty").notEmpty();
  req.assert("otp", "OTP cannot be empty").notEmpty();
  req.sanitize("email").normalizeEmail({
    gmail_remove_dots: false
  });
  // req.assert('password', 'Password must be at least 4 characters long').len(4);
  // req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    return res.status(400).json({
      errors: errors
    });
  }
  // console.log(req.query.email, req.query.token);
  try {
    User.query()
      .where("email", req.body.email)
      .where("otp", req.body.otp)
      .first()
      .then(async function (user) {
        // console.log(user);
        if (!user) {
          return res.status(500).send({
            msg: "User not found"
          });
        }
        if (user.is_verified) {
          return res.status(500).send({
            msg: "User is already verified"
          });
        }
        // if (!user.token === req.query.token) {
        //   return res.status(500).send({
        //     msg: "Invalid or expired token."
        //   });
        // }
        // user.is_verified = true;
        try {
          const updatedUser = await User.query().patchAndFetchById(user.id, {
            is_verified: true,
            otp: null
          });
          console.log(
            "id:",
            updatedUser.id,
            updatedUser.email,
            "verified:",
            updatedUser.is_verified
          );
          const msg = {
            msg: "User with email " +
              user.email +
              "has been successfully verified."
          };
          res.status(200).send(msg);
          // res.status(200).send('<html><body>User with email ' + user.email + ' has been verified.Click <a href="/">here to login</a>.</body></html>');
          // return res.redirect('/auth/login?');
        } catch (e) {
          return res.status(500).send({
            msg: e.message
          });
        }
      })
      .catch(function (err) {
        return res.status(500).send({
          msg: err.message
        });
      });
  } catch (err) {
    errorHandler(err, res);
    return;
  }
};

function handleResponse(res, code, statusMsg) {
  res.status(code).json(statusMsg);
}