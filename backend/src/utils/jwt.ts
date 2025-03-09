import { User } from "@prisma/client";
import jwt, { SignOptions } from "jsonwebtoken";

/**
 * Issues a JWT token for a given user.
 *
 * @param {User} user - The user object containing the user's ID and role.
 * @returns {string} A signed JWT token.
 * @throws {Error} If JWT_SECRET is not defined.
 */
export function issueToken(user: User): string {
  if (!process.env.JWT_SECRET || !process.env.JWT_EXPIRES_IN) {
    throw new Error("JWT_SECRET or JWT_EXPIRES_IN is not defined");
  }

  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET as string,
    {
      expiresIn: process.env.JWT_EXPIRES_IN,
    } as SignOptions
  );
}

/**
 * Verifies a JWT token and returns the decoded payload.
 *
 * @param {string} token - The JWT token to verify.
 * @returns {object | string} The decoded token payload.
 * @throws {Error} If JWT_SECRET is not defined or verification fails.
 */
export function verifyToken(token: string): object | string {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined");
  }

  return jwt.verify(token, process.env.JWT_SECRET);
}
