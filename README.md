# p4ssw0rd

[![Build Status](https://travis-ci.com/Munkkeli/p4ssw0rd.svg?branch=master)](https://travis-ci.com/Munkkeli/p4ssw0rd)

Generates secure password hashes with SHA-256 and bcrypt. Supports TypeScript.

```bash
npm install p4ssw0rd
```

```js
import * as p4ssw0rd from 'p4ssw0rd';
```

- No password length limit
- Output hash is always 60
- Configurable bcrypt cost
- Only one dependency!

Uses [bcrypt.js](https://github.com/dcodeIO/bcrypt.js) to generate the bcrypt hash. For SHA-512 hash the [Node.js Crypto Module](https://nodejs.org/api/crypto.html) is used.

## Usage

### Hash

```js
const hash = p4ssw0rd.hash(password, options?);
```

Creates a hash from supplied password. Hash will always be 60 characters long.

### Check

```js
if (p4ssw0rd.check(password, hash, options?)) {
  // Passwords match
}
```

Validates the input password against a stored hash. Returns true if password is correct.

### Simulate

```js
p4ssw0rd.simulate();
```

Simulates validating a real hash. Usefull against timing attacks on login pages.

### Options

```js
{
  cost: 10, // The "cost" of bcrypt hash, default is 10
}
```

## Contributing

1. Clone the git repository
2. `npm install` (Make sure `NODE_ENV` is not set to `production`)
3. Make changes
4. `npm run build`
5. `npm test`
