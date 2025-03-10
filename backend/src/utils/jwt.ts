import { User } from "@prisma/client";
import jwt, { JwtPayload, SignOptions } from "jsonwebtoken";

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
    { sub: user.id, role: user.role },
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
 * @returns {JwtPayload | string}
 * @throws {Error} If JWT_SECRET is not defined or verification fails.
 */
export function verifyToken(token: string): JwtPayload {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined");
  }
  const verifiedToken = jwt.verify(token, process.env.JWT_SECRET) as JwtPayload;

  return verifiedToken;
}

/**
 * Generates a JWT token for email verification.
 *
 * @param {string} userId - The unique identifier of the user.
 * @param {string} email - The email address of the user.
 * @returns {string} The signed JWT token.
 * @throws {Error} If the `JWT_SECRET` environment variable is not defined.
 */
export function generateEmailVerificationToken(
  userId: string,
  email: string
): string {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined in the environment variables.");
  }

  return jwt.sign({ sub: userId, email }, process.env.JWT_SECRET, {
    expiresIn: "24h",
  });
}
