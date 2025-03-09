import { NextFunction, Request, Response } from "express";
import { AuthService } from "./auth.service";
import { HttpStatus } from "@/constants/httpStatus";
import { issueToken } from "@/utils/jwt";
import { LoginRequestBody, RegisterRequestBody } from "./auth.types";
const auth = new AuthService();
/**
 * Authentication contoller for handling incoming requst and handle the response.
 */
/**
 * Controller responsible for handling authentication-related operations.
 * Provides endpoints for user registration and login functionality.
 * Uses secure cookie-based token authentication with CSRF protection.
 *
 * @class AuthController
 * @description Manages user authentication operations including registration and login
 */
export class AuthController {
  /**
   * Registers a new user, generates an authentication token, and sets it as an HTTP-only cookie.
   *
   * This function takes user details from the request body, creates a new user,
   * issues a JSON Web Token (JWT), and returns a success response.
   *
   * - On success:
   *   - Returns HTTP 201 (Created) status.
   *   - Sets an `access_token` cookie with security configurations.
   *   - Sends a response confirming user creation.
   *
   * - On failure:
   *   - Calls `next(error)` to pass the error to the global error handler.
   *
   * @param {Request} req - The Express request object containing user details in `req.body`.
   * @param {Response} res - The Express response object for sending responses.
   * @param {NextFunction} next - The next middleware function for error handling.
   * @returns {Promise<void>} Resolves when the response is sent or an error is passed to `next()`.
   */
  static async register(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { name, email, password } = req.body as RegisterRequestBody;
      const user = await auth.register(name, email, password);
      const token = issueToken(user);

      res
        .status(HttpStatus.CREATED)
        .cookie("access_token", token, {
          httpOnly: true,
          sameSite: "strict", // CSRF protection
          secure: process.env.NODE_ENV === "production", // Secure only in production
          maxAge: 1 * 24 * 60 * 60 * 1000, // Expires in 1 day
        })
        .header("Authorization", token)
        .json({ message: "User created successfully" });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Authenticates a user by verifying their email and password, then issues a JWT token.
   *
   * - On success:
   *   - Returns HTTP 200 (OK) status.
   *   - Sets an `access_token` cookie with security configurations.
   *   - Includes the token in the `Authorization` header.
   *   - Sends a JSON response confirming successful login.
   *
   * - On failure:
   *   - Calls `next(error)` to pass the error to the global error handler.
   *
   * @param {Request} req - The Express request object containing login credentials in `req.body`.
   * @param {Response} res - The Express response object for sending responses.
   * @param {NextFunction} next - The next middleware function for error handling.
   * @returns {Promise<void>} Resolves when the response is sent or an error is passed to `next()`.
   */
  static async login(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { email, password } = req.body as LoginRequestBody;
      const user = await auth.login(email, password);
      const token = issueToken(user);

      res
        .status(HttpStatus.OK)
        .cookie("access_token", token, {
          httpOnly: true,
          sameSite: "strict", // CSRF protection
          secure: process.env.NODE_ENV === "production", // Secure only in production
          maxAge: 1 * 24 * 60 * 60 * 1000, // Expires in 1 day
        })
        .header("Authorization", token)
        .json({ message: "User logged in successfully" });
    } catch (error) {
      next(error);
    }
  }
}
