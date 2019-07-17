"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var bcryptjs_1 = __importDefault(require("bcryptjs"));
var crypto_1 = require("crypto");
var defaultOptions = {
    cost: 10,
};
/* Generate a SHA-256 hash */
var createSha256 = function (value) {
    return crypto_1.createHash('sha256')
        .update(value)
        .digest('base64');
};
/* Generate a hash from a password */
exports.hash = function (password, options) {
    var cost = __assign({}, defaultOptions, options).cost;
    var sha256 = createSha256(password);
    var salt = bcryptjs_1.default.genSaltSync(cost);
    var hash = bcryptjs_1.default.hashSync(sha256, salt);
    return hash;
};
/* Check password against a hash */
exports.check = function (password, hash, options) {
    var sha256 = createSha256(password);
    var valid = bcryptjs_1.default.compareSync(sha256, hash);
    return valid;
};
/* Simulate checking a password */
exports.simulate = function (options) {
    var cost = __assign({}, defaultOptions, options).cost;
    var password = crypto_1.randomBytes(64).toString('latin1');
    var hash = "$2a$" + cost + "$" + crypto_1.randomBytes(26).toString('hex') + "O";
    exports.check(password, hash);
};
