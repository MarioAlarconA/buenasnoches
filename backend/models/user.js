const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/config').get(process.env.NODE_ENV);
const SALT_I = 10;

const userSchema = mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    firstname: {
        type: String,
        maxlength: 100
    },
    lastname: {
        type: String,
        maxlength: 100
    },
    token: {
        type: String
    }
});

userSchema.pre('save', async function (next) {
    var user = this;
    if (user.isModified('password')) {
        try {
            const salt = await bcrypt.genSalt(SALT_I);
            const hash = await bcrypt.hash(user.password, salt);
            user.password = hash;
            next();
        } catch (err) {
            return next(err);
        }
    } else {
        next();
    }
});
userSchema.methods.comparepassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};
userSchema.methods.generateToken = function (cb) {
    var user = this;
    var token = jwt.sign(user._id.toHexString(), config.SECRET);
    user.token = token;
    user.save(function (err, user) {
        if (err) return cb(err);
        cb(null, user);
    });
};
userSchema.statics.findByToken = function (token, cb) {
    var user = this;
    jwt.verify(token, config.SECRET, function (err, decode) {
        user.findOne({ "_id": decode, "token": token }, function (err, user) {
            if (err) return cb(err);
            cb(null, user);
        });
    });
};
userSchema.methods.deleteToken = function (token, cb) {
    var user = this;
    user.updateOne({ $unset: { token: 1 } }, function (err, raw) {
        if (err) return cb(err);
        cb(null, user);
    });
};
const User = mongoose.model('User', userSchema);

module.exports = User;