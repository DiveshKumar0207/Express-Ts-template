import { randomBytes, pbkdf2Sync } from "crypto";

const hashPassword = (password: string): { salt: string; hash: string } => {
  const salt = randomBytes(16).toString("hex"); // Generate a random salt
  const iterations = 10000; // Number of iterations
  const keylen = 64; // Length of the resulting hash
  const digest = "sha512"; // Digest algorithm

  const hash = pbkdf2Sync(password, salt, iterations, keylen, digest).toString(
    "hex"
  );

  return { salt, hash };
};

const verifyPassword = (
  password: string,
  salt: string,
  storedHash: string
): boolean => {
  const iterations = 10000;
  const keylen = 64;
  const digest = "sha512";

  const hash = pbkdf2Sync(password, salt, iterations, keylen, digest).toString(
    "hex"
  );

  return hash === storedHash;
};

export { hashPassword, verifyPassword };
