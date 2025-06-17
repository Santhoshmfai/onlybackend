import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import dotenv from "dotenv";
import Resume from "../models/Resume.js";
import jwt from "jsonwebtoken";
dotenv.config();

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const user = await Resume.findById(id);
    done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
    let existingUser = await Resume.findOne({ googleId: profile.id });

    if (!existingUser) {
        existingUser = await Resume.create({
               googleId: profile.id,
    username: profile.displayName, // ✅ required field
    email: profile.emails[0].value,
    profilePicture: profile.photos[0].value,
    password: null,
    displayName: profile.displayName 
        });
    }

    done(null, existingUser);
}));
