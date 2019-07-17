import * as p4ssw0rd from '../src/index';
import { expect } from 'chai';
import { randomBytes } from 'crypto';
import blns from './blns.json';

describe('Hash', () => {
  it('should hash a basic password', () => {
    const hash = p4ssw0rd.hash('admin123');

    expect(hash.length).to.equal(60);
    expect(hash.split('$').length).to.equal(4);
    expect(/^\$2[ayb]\$.{56}$/.test(hash)).to.equal(true);
  });

  it('should create a unique hash every time', () => {
    const hash = p4ssw0rd.hash('admin123');

    for (let i = 0; i < 8; i++) {
      expect(p4ssw0rd.hash('admin123')).not.equal(hash);
    }
  });

  it('should respect the cost option', () => {
    const hash = p4ssw0rd.hash('admin123', { cost: 8 });

    expect(hash.split('$')[2]).to.equal('08');
  });

  it('should accept any string as valid input', () => {
    const list = [];
    for (const value of blns) {
      const hash = p4ssw0rd.hash(value, { cost: 4 });

      expect(hash.length).to.equal(60);
      expect(hash.split('$').length).to.equal(4);
      expect(/^\$2[ayb]\$.{56}$/.test(hash)).to.equal(true);
      expect(list.includes(hash)).to.equal(false);

      list.push(hash);
    }
  });
});

describe('Check', () => {
  it('should validate matching passwords', () => {
    const hash = p4ssw0rd.hash('admin123');
    const valid = p4ssw0rd.check('admin123', hash);

    expect(valid).to.equal(true);
  });

  it('should fail with incorrect passwords', () => {
    const hash = p4ssw0rd.hash('admin123');
    const valid = p4ssw0rd.check('password123', hash);

    expect(valid).to.equal(false);
  });

  it('should fail with very similar passwords', () => {
    const password = 'admin123';
    const hash = p4ssw0rd.hash(password, { cost: 4 });

    const characterMap = [
      'ABCDEFGHIJKLMNOPQRSTUVTXYZÅÄÖ',
      'abcdefghijklmnopqrstuvwxyzåäö',
      '0123456789+-*/$@#& %[](){}?.,',
    ].join();

    for (let i = 0; i < 512; i++) {
      let compare = password;
      for (let o = 0; o < 1 + Math.random() * 2; o++) {
        let index = Math.floor(Math.random() * 7);
        let character =
          characterMap[Math.floor(Math.random() * characterMap.length)];

        compare =
          compare.substr(0, index) +
          character +
          (compare.substr(index + 1) || '');
      }

      const valid = p4ssw0rd.check(compare, hash);

      expect(valid).to.equal(compare === password);
    }
  });

  it('should accept any string as valid input', () => {
    for (const value of blns) {
      const hash = p4ssw0rd.hash(value, { cost: 4 });
      const valid = p4ssw0rd.check(value, hash);

      expect(valid).to.equal(true);
    }
  });
});

describe('Simulate', () => {
  it('should take the same amount of time as actual check', () => {
    const hash = p4ssw0rd.hash('admin123', { cost: 12 });

    let actual = Date.now();
    p4ssw0rd.check('admin123', hash);
    actual = Date.now() - actual;

    let fake = Date.now();
    p4ssw0rd.simulate({ cost: 12 });
    fake = Date.now() - fake;

    expect(Math.abs(actual - fake)).to.lessThan(100);
  });

  it('should respect the cost option', () => {
    let fast = Date.now();
    p4ssw0rd.simulate({ cost: 8 });
    fast = Date.now() - fast;

    let slow = Date.now();
    p4ssw0rd.simulate({ cost: 12 });
    slow = Date.now() - slow;

    expect(fast).to.lessThan(slow);
  });
});

describe('Security', () => {
  it('should allow long passwords', () => {
    const password = randomBytes(64).toString('hex');
    const long = password;
    const medium = password.substring(0, 96);
    const short = password.substring(0, 32);

    const list = [long, medium, short];

    for (let i = 0; i < 32; i++) {
      for (const value of list) {
        const hash = p4ssw0rd.hash(value, { cost: 4 });

        for (const compare of list) {
          const valid = p4ssw0rd.check(compare, hash);

          expect(valid).to.equal(value === compare);
        }
      }
    }
  });

  it('should not create obvious collisions', () => {
    const list: string[] = [];

    for (let i = 0; i < 32; i++) {
      let password = null;
      do {
        password = randomBytes(16).toString('hex');
        if (list.includes(password)) password = null;
      } while (!password);

      list.push(password);

      const hash = p4ssw0rd.hash(password, { cost: 4 });

      for (const compare of list) {
        const valid = p4ssw0rd.check(compare, hash);

        expect(valid).to.equal(password === compare);
      }
    }
  });
});
