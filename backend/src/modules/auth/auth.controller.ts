import { NextFunction, Request, Response } from "express";
import { AuthService } from "./auth.service";
import { HttpStatus } from "@/constants/httpStatus";
import { issueToken } from "@/utils/jwt";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import { LoginRequestBody, RegisterRequestBody } from "./auth.types";
import { User } from "@/config/db";
import { User as UserType } from "@prisma/client";
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
      const { email, password, token: mfaToken } = req.body as LoginRequestBody;
      const user = await auth.login(email, password);

      if (user.mfaEnabled) {
        if (!mfaToken) {
          res.status(HttpStatus.BAD_REQUEST).json({
            message: "MFA token required",
          });
          return;
        }

        const isValidMFA = speakeasy.totp.verify({
          secret: user.mfaSecret!,
          encoding: "base32",
          token: mfaToken,
          window: 1,
        });

        if (!isValidMFA) {
          res.status(HttpStatus.UNAUTHORIZED).json({
            message: "Invalid MFA code",
          });
          return;
        }
      }

      const token = issueToken(user);

      res
        .status(HttpStatus.OK)
        .cookie("access_token", token, {
          httpOnly: true,
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production",
          maxAge: 24 * 60 * 60 * 1000, // 1 day
        })
        .header("Authorization", token)
        .json({ message: "User logged in successfully" });
    } catch (error) {
      next(error);
    }
  }
  /**
   * Logout a user by clearing the `access_token` cookie.
   * @param {Request} req
   * @param {Response} res
   * @param {NextFunction} next
   * @returns {Promise<void>} Resolves when the response is sent or an error is passed to `next()`.
   */
  static async logout(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      res.clearCookie("access_token").json({ message: "User logged out" });
    } catch (error) {
      next(error);
    }
  }
  /**
   * Enable Multi-Factor Authentication (MFA) for the currently authenticated user.
   * @description Generates a secret key and a QR code for the user to scan and enable MFA.
   * @param {Request} req
   * @param {Response} res
   * @param {NextFunction} next
   * @returns {Promise<void>} Resolves when the response is sent or an error is passed to `next()`.
   */
  static async enableMFA(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    const userId = (req.user as UserType)?.id;
    const secret = speakeasy.generateSecret({ length: 20 });
    try {
      const user = await User.update({
        where: { id: userId },
        data: { mfaSecret: secret.base32 },
      });
      // Generate QR code (for Google Authenticator)
      const otpauthUrl = secret.otpauth_url!;
      const qrCode = await qrcode.toDataURL(otpauthUrl);
      await auth.sendMFAEnabledEmail(user.email, user.name);
      res.status(HttpStatus.CREATED).json({ qrCode, secret: secret.base32 });
    } catch (error) {
      next(error);
    }
  }
  /**
   * Verifies the Multi-Factor Authentication (MFA) token for a user.
   *
   * @param {Request} req - Express request object containing the user ID in `req.user` and MFA token in `req.body.token`
   * @param {Response} res - Express response object to send the verification result
   * @param {NextFunction} next - Express next function for error handling
   *
   * @returns {Promise<void>} - Sends a response indicating success or failure of MFA verification.
   */
  static async verifyMFA(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      // Ensure user is authenticated
      const userId = (req.user as UserType)?.id;

      // Extract token from request body
      const { token } = req.body;
      // Fetch user's MFA secret from database
      const user: Pick<UserType, "mfaSecret"> | null = await User.findUnique({
        where: { id: userId },
        select: { mfaSecret: true },
      });

      // Check if MFA is enabled for the user
      if (!user || !user.mfaSecret) {
        res
          .status(HttpStatus.FORBIDDEN)
          .json({ message: "MFA is not enabled for this user" });
        return;
      }

      // Verify the provided MFA token
      const verified = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: "base32",
        token,
        window: 1,
      });

      // Respond based on verification result
      if (verified) {
        res
          .status(HttpStatus.OK)
          .json({ message: "MFA verified successfully" });
      } else {
        res
          .status(HttpStatus.UNAUTHORIZED)
          .json({ message: "Invalid MFA token" });
      }
    } catch (error) {
      next(error);
    }
  }
}
