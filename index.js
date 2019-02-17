const express = require("express");
const HttpError = require('http-errors')

const Passport = require("passport");
const PassportLocal = require("passport-local").Strategy;

module.exports = (app, path, options) => {
    options.emailField = options.emailField || "email";
    options.usernameField = options.usernameField || "username";
    options.passwordField = options.passwordField || "password";
    options.registerFlag = options.registerFlag || "isNew";
    options.registerRequiresEmail = options.registerRequiresEmail || false;

    if (!(typeof options.model === "string")) {
        throw new Error(`options.model must be a string`);
    }

    const router = express.Router();

    router.use(Passport.initialize());

    let User = app.connection.model(options.model);

    Passport.use(new PassportLocal({
        usernameField: options.usernameField,
        passwordField: options.passwordField,
        passReqToCallback: true
    }, async (req, username, password, done) => {
        const query = {};
        const registerFlag = req.body[options.registerFlag];

        query[options.usernameField] = username;

        try {
            const user = await User.findOne(query);

            if (user) { 
                if (registerFlag) {
                    return done(null, false, { code: "usernameAlreadyInUse", message: "Username is already taken" });
                } else {
                    if (await user.comparePassword(password)) {
                        return done(null, user);
                    } else {
                        return done(null, false, { code: "invalidCredentials", message: "Username / Password is invalid" });
                    }
                }
            } else {
                if (registerFlag) {
                    const paras = {};
                    paras[options.usernameField] = username;
                    paras[options.passwordField] = password;

                    if (options.registerRequiresEmail)
                        if (!req.body[options.emailField]) return done(null, false, { code: "emailRequired", message: "Email not supplied" });
                        else paras[options.emailField] = req.body[options.emailField];

                    const newUser = new User(paras);
                    await newUser.save();

                    return done(null, newUser);
                } else {
                    return done(null, false, { code: "invalidCredentials", message: "Username / Password is invalid" });
                }
            }
        } catch (error) {
            return done(error);
        }
    }));

    router.post("/", (req, res, next) => {
        if (options.routeRootOverride) {
            return options.routeRootOverride(req, res, next);
        }

        Passport.authenticate("local", function(err, user, info) {
            if (options.authFunction) {
                return options.authFunction(req, res, next, err, user, info);
            }

            if (user) {
                return res.status(200);
            } else {
                if (info && info.code)
                    return next({ status: 400, code: info.code, message: info.message });
                else
                    return next({ status: 400, code: "unknown", message: "Unknown error" });
            }
        }) (req, res, next);
    });

    router.post([ options.routeChange || "/change" ], async (req, res, next) => {
        if (!req.body[options.usernameField]) {
            return next({ status: 400, code: "invalidParameter", message: "Username not supplied" });
        }

        if (!req.body[options.passwordField]) {
            return next({ status: 400, code: "invalidParameter", message: "Username not supplied" });
        }

        if (!req.body.newPassword) {
            return next({ status: 400, code: "invalidParameter", message: "Username not supplied" });
        }

        const query = {};
        query[options.usernameField] = req.body[options.usernameField];

        try {
            const user = await User.findOne(query);
            
            if (user) { 
                await user.changePassword(req.body[options.passwordField], req.body.newPassword);

                return res.send(200);
            } else {
                return next({ status: 400, code: "invalidCredentials", message: "Username / Password is invalid" });
            }
        } catch (error) {
            next(error);
        }
    });

    return router;
};
