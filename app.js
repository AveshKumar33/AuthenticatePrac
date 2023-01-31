const bcrypt = require('bcryptjs');
const express = require("express");
const { body, validationResult } = require('express-validator');
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const { dirname } = require('path');
const Schema = mongoose.Schema;
require('dotenv').config();
const app = express();
const mongoDb = `mongodb+srv://AveshKumar:${process.env.password}@cluster0.yz9qswz.mongodb.net/authentcate?retryWrites=true&w=majority`;

mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
    "User",
    new Schema({
        username: { type: String, required: true ,unique:true},
        password: { type: String, required: true }
    })
);


app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));

//Function one : setting up the LocalStrategy 

passport.use(
    new LocalStrategy((username, password, done) => {
        User.findOne({ username: username }, (err, user) => {
            if (err) {
                return done(err);
            }
            if (!user) {
                return done(null, false, { message: "Incorrect username" });
            }
            bcrypt.compare(password, user.password, (err, res) => {
                if (res) {
                    // passwords match! log user in 
                    return done(null, user)
                } else {
                    // passwords do not match! 
                    return done(null, false, { message: "Incorrect password" })
                }
            })
        });
    })
);


app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});


app.use(function (req, res, next) {
    res.locals.currentUser = req.user;
    next();
});
// now from here starting all get methods related API  
//To get index page            
app.get("/", (req, res) => res.render("index", { title: 'welcome my authentication app' }));
//To get sign-up success page
app.get("/signsuccess", (req, res) => res.render("index", { title: 'user register successfully' }));
//To get log-in success page
app.get("/loginsuccess", (req, res) => {
    res.render("log-in", { user: req.user });
});
//To get log-out success page
app.get("/logoutsuccess", (req, res) => res.render("index", { title: ' user successfully log-out' }));
// To get sign-up page 
app.get("/sign-up", (req, res) => res.render("sign-up-form"));
//To get log-in page
app.get("/log-in", (req, res) => {
    res.render("log-in", { user: req.user })
});
//To get log-out page
app.get("/log-out", (req, res) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect("/logoutsuccess");
    });
});
// from here all post routing start 
// For post sign-up form data
app.post("/sign-up", [
        body('username').trim().isEmail().normalizeEmail().isLowercase().withMessage('please enter valid mail')
        .custom(value => {
            
            return User.findOne({username:value}).then(user => {
              if (user) {
                return Promise.reject('E-mail already in use');
              }
            });
          }),
    body('password')
        .not()
        .trim()
        .isLength({ min: 5 })
        .withMessage('please enter the valid password'),

], (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log(errors);
        res.render('sign-up-form', { errors: errors.array() });
        res.send();
    }
    else{
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
        if(err){
            res.send('something went wrong ',err);
        }
        else{
        try {
            await User.create({ username: req.body.username, password: hashedPassword });
            res.redirect("/signsuccess");
        } catch (err) {
            return next(err)
        }
    }
    });
}
});
//For post log-in form data
app.post(
    "/log-in",[body('username')
    .trim().isEmail().normalizeEmail().isLowercase().withMessage('please enter valid mail'),
    body('password').not().trim().isLength({min:5}).withMessage('please enter valid password')
],
    passport.authenticate("local", {
        successRedirect: "/loginsuccess",
        failureRedirect: "/log-in"
    })
);



app.listen(3000, () => console.log("app listening on port 3000!"));
