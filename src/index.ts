import bcrypt from 'bcryptjs';
import { createHash, randomBytes } from 'crypto';

export interface HashOptions {
  cost: number;
}

const defaultOptions = {
  cost: 10,
} as HashOptions;

/* Generate a SHA-256 hash */
const createSha256 = (value: string) =>
  createHash('sha256')
    .update(value)
    .digest('base64');

/* Generate a hash from a password */
export const hash = (password: string, options?: Partial<HashOptions>) => {
  const { cost } = { ...defaultOptions, ...options };

  const sha256 = createSha256(password);
  const salt = bcrypt.genSaltSync(cost);
  const hash = bcrypt.hashSync(sha256, salt);

  return hash;
};

/* Check password against a hash */
export const check = (
  password: string,
  hash: string,
  options?: Partial<HashOptions>
) => {
  const sha256 = createSha256(password);
  const valid = bcrypt.compareSync(sha256, hash);

  return valid;
};

/* Simulate checking a password */
export const simulate = (options?: Partial<HashOptions>) => {
  const { cost } = { ...defaultOptions, ...options };

  const password = randomBytes(64).toString('latin1');
  const hash = `$2a$${cost}$${randomBytes(26).toString('hex')}O`;

  check(password, hash);
};
