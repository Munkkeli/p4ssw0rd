"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var p4ssw0rd = __importStar(require("../src/index"));
var chai_1 = require("chai");
var crypto_1 = require("crypto");
var blns_json_1 = __importDefault(require("./blns.json"));
describe('Hash', function () {
    it('should hash a basic password', function () {
        var hash = p4ssw0rd.hash('admin123');
        chai_1.expect(hash.length).to.equal(60);
        chai_1.expect(hash.split('$').length).to.equal(4);
        chai_1.expect(/^\$2[ayb]\$.{56}$/.test(hash)).to.equal(true);
    });
    it('should create a unique hash every time', function () {
        var hash = p4ssw0rd.hash('admin123');
        for (var i = 0; i < 8; i++) {
            chai_1.expect(p4ssw0rd.hash('admin123')).not.equal(hash);
        }
    });
    it('should respect the cost option', function () {
        var hash = p4ssw0rd.hash('admin123', { cost: 8 });
        chai_1.expect(hash.split('$')[2]).to.equal('08');
    });
    it('should accept any string as valid input', function () {
        var list = [];
        for (var _i = 0, blns_1 = blns_json_1.default; _i < blns_1.length; _i++) {
            var value = blns_1[_i];
            var hash = p4ssw0rd.hash(value, { cost: 4 });
            chai_1.expect(hash.length).to.equal(60);
            chai_1.expect(hash.split('$').length).to.equal(4);
            chai_1.expect(/^\$2[ayb]\$.{56}$/.test(hash)).to.equal(true);
            chai_1.expect(list.includes(hash)).to.equal(false);
            list.push(hash);
        }
    });
});
describe('Check', function () {
    it('should validate matching passwords', function () {
        var hash = p4ssw0rd.hash('admin123');
        var valid = p4ssw0rd.check('admin123', hash);
        chai_1.expect(valid).to.equal(true);
    });
    it('should fail with incorrect passwords', function () {
        var hash = p4ssw0rd.hash('admin123');
        var valid = p4ssw0rd.check('password123', hash);
        chai_1.expect(valid).to.equal(false);
    });
    it('should fail with very similar passwords', function () {
        var password = 'admin123';
        var hash = p4ssw0rd.hash(password, { cost: 4 });
        var characterMap = [
            'ABCDEFGHIJKLMNOPQRSTUVTXYZÅÄÖ',
            'abcdefghijklmnopqrstuvwxyzåäö',
            '0123456789+-*/$@#& %[](){}?.,',
        ].join();
        for (var i = 0; i < 512; i++) {
            var compare = password;
            for (var o = 0; o < 1 + Math.random() * 2; o++) {
                var index = Math.floor(Math.random() * 7);
                var character = characterMap[Math.floor(Math.random() * characterMap.length)];
                compare =
                    compare.substr(0, index) +
                        character +
                        (compare.substr(index + 1) || '');
            }
            var valid = p4ssw0rd.check(compare, hash);
            chai_1.expect(valid).to.equal(compare === password);
        }
    });
    it('should accept any string as valid input', function () {
        for (var _i = 0, blns_2 = blns_json_1.default; _i < blns_2.length; _i++) {
            var value = blns_2[_i];
            var hash = p4ssw0rd.hash(value, { cost: 4 });
            var valid = p4ssw0rd.check(value, hash);
            chai_1.expect(valid).to.equal(true);
        }
    });
});
describe('Simulate', function () {
    it('should take the same amount of time as actual check', function () {
        var hash = p4ssw0rd.hash('admin123', { cost: 12 });
        var actual = Date.now();
        p4ssw0rd.check('admin123', hash);
        actual = Date.now() - actual;
        var fake = Date.now();
        p4ssw0rd.simulate({ cost: 12 });
        fake = Date.now() - fake;
        chai_1.expect(Math.abs(actual - fake)).to.lessThan(100);
    });
    it('should respect the cost option', function () {
        var fast = Date.now();
        p4ssw0rd.simulate({ cost: 8 });
        fast = Date.now() - fast;
        var slow = Date.now();
        p4ssw0rd.simulate({ cost: 12 });
        slow = Date.now() - slow;
        chai_1.expect(fast).to.lessThan(slow);
    });
});
describe('Security', function () {
    it('should allow long passwords', function () {
        var password = crypto_1.randomBytes(64).toString('hex');
        var long = password;
        var medium = password.substring(0, 96);
        var short = password.substring(0, 32);
        var list = [long, medium, short];
        for (var i = 0; i < 32; i++) {
            for (var _i = 0, list_1 = list; _i < list_1.length; _i++) {
                var value = list_1[_i];
                var hash = p4ssw0rd.hash(value, { cost: 4 });
                for (var _a = 0, list_2 = list; _a < list_2.length; _a++) {
                    var compare = list_2[_a];
                    var valid = p4ssw0rd.check(compare, hash);
                    chai_1.expect(valid).to.equal(value === compare);
                }
            }
        }
    });
    it('should not create obvious collisions', function () {
        var list = [];
        for (var i = 0; i < 32; i++) {
            var password = null;
            do {
                password = crypto_1.randomBytes(16).toString('hex');
                if (list.includes(password))
                    password = null;
            } while (!password);
            list.push(password);
            var hash = p4ssw0rd.hash(password, { cost: 4 });
            for (var _i = 0, list_3 = list; _i < list_3.length; _i++) {
                var compare = list_3[_i];
                var valid = p4ssw0rd.check(compare, hash);
                chai_1.expect(valid).to.equal(password === compare);
            }
        }
    });
});
