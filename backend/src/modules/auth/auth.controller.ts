import { NextFunction, Request, Response } from "express";
import { AuthService } from "./auth.service";
import { HttpStatus } from "@/constants/httpStatus";
import {
  generateEmailVerificationToken,
  issueToken,
  verifyToken,
} from "@/utils/jwt";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import {
  LoginRequestBody,
  MFAMethods,
  RegisterRequestBody,
  ResetPasswordData,
} from "./auth.types";
import crypto from "crypto";
import { User } from "@/config/db";
import { User as UserType } from "@prisma/client";
import bcrypt from "bcrypt-ts";
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
      const { username, email, password } = req.body as RegisterRequestBody;
      const user = await auth.register(username, email, password);

      const emailToken = generateEmailVerificationToken(user.id, email);
      await auth.sendEmailVerification(email, username, emailToken);
      res
        .status(HttpStatus.CREATED)

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
      const {
        email,
        password,
        token: mfaToken,
        mfaType,
        emailOtpCode,
      } = req.body as LoginRequestBody;

      const user = await auth.login(email, password);
      const mfaMethods = (user?.mfaMethods ?? {}) as MFAMethods;

      if (user.mfaEnabled && mfaMethods?.TOTP && mfaType === "TOTP") {
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
        } else {
          if (emailOtpCode) {
            const user = await User.findUnique({ where: { email } });

            if (!user || !user.emailOtp || !user.emailOtpExpires) {
              res.status(HttpStatus.UNAUTHORIZED).json({
                message: "Invalid MFA code",
              });
              return;
            }

            const isOtpValid = user.emailOtp === emailOtpCode;
            const isOtpExpired = new Date(user.emailOtpExpires) < new Date();

            if (!isOtpValid || isOtpExpired) {
              res.status(HttpStatus.UNAUTHORIZED).json({
                message: isOtpExpired ? "MFA code expired" : "Invalid MFA code",
              });
              return;
            }

            await User.update({
              where: { email },
              data: {
                emailOtp: null,
                emailOtpExpires: null,
              },
            });

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

            return;
          }
          // Generate a random 8-digit OTP
          const emailOtp =
            Math.floor(Math.random() * (10000000 - 99999999 + 1)) + 10000000;

          // Save OTP to the database with expiration (e.g., 5 minutes)
          await User.update({
            where: { id: user.id },
            data: {
              emailOtp,
              emailOtpExpires: new Date(Date.now() + 5 * 60 * 1000), // Expires in 5 minutes
            },
          });

          // Send the OTP via email
          await auth.sendEmailMFA(user.email, user.username, emailOtp);

          res.status(HttpStatus.ACCEPTED).json({
            message: "MFA code sent to your email. Please verify to proceed.",
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

    const mfaType = req.params.mfatype as "Email" | "TOTP";
    if (mfaType !== "Email" && mfaType !== "TOTP") {
      res.status(HttpStatus.BAD_REQUEST).json({
        error: "Invalid MFA type. Choose 'Email' or 'TOTP'.",
        validOptions: ["Email", "TOTP"],
      });
      return;
    }

    try {
      const userMfaTypeCheck = await User.findUnique({
        where: { id: userId },
      });
      if (!userMfaTypeCheck) {
        res.status(HttpStatus.NOT_FOUND).json({ message: "User not found" });
        return;
      }

      // Get existing MFA methods or initialize an empty object
      const existingMfaMethods =
        (userMfaTypeCheck.mfaMethods as MFAMethods) || {};

      if (mfaType === "TOTP") {
        // Check if TOTP is already enabled
        if (existingMfaMethods.TOTP) {
          res
            .status(HttpStatus.CONFLICT)
            .json({ message: "TOTP MFA is already enabled." });
          return;
        }

        // Generate a new secret for TOTP
        const secret = speakeasy.generateSecret({ length: 20 });

        // Update user with new MFA settings
        const user = await User.update({
          where: { id: userId },
          data: {
            mfaSecret: secret.base32,
            mfaEnabled: true,
            mfaMethods: {
              set: { ...existingMfaMethods, TOTP: true }, // Merge existing methods
            },
          },
        });

        // Generate QR code
        const otpauthUrl = secret.otpauth_url!;
        const qrCode = await qrcode.toDataURL(otpauthUrl);

        // Send MFA activation email
        await auth.sendMFAEnabledEmail(user.email, user.username, mfaType);

        res.status(HttpStatus.CREATED).json({ qrCode, secret: secret.base32 });
        return;
      } else {
        if (existingMfaMethods.Email) {
          res
            .status(HttpStatus.CONFLICT)
            .json({ message: "Email MFA is already enabled." });
          return;
        }

        const user = await User.update({
          where: { id: userId },
          data: {
            mfaMethods: {
              set: { ...existingMfaMethods, email: true }, // Merge existing methods
            },
            mfaEnabled: true,
          },
        });

        await auth.sendMFAEnabledEmail(user.email, user.username, mfaType);

        res.status(HttpStatus.CREATED).json({
          message: "Email MFA enabled successfully.",
        });
        return;
      }
    } catch (error) {
      next(error);
    }
  }
  // FIXME: test this code when you build the front end to get the qrcode to scan
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
  /**
   * Verifies a user's email using the verification token.
   *
   * @param {Request} req - Express request containing the verification token
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next function for error handling
   * @returns {Promise<void>} Resolves when email is verified or error is passed to next()
   */
  static async emailVerification(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { token } = req.query;

      if (!token || typeof token !== "string") {
        res.status(HttpStatus.BAD_REQUEST).json({
          message: "Verification token is required",
        });
        return;
      }

      const verfiedToken = verifyToken(token);

      await User.update({
        where: { id: verfiedToken.sub },
        data: { isVerified: true },
      });

      res.status(HttpStatus.OK).json({
        message: "Email verified successfully",
      });
    } catch (error) {
      next(error);
    }
  }
  /**
   * Generates backup codes for a user's two-factor authentication.
   *
   * @param {Request}  req - Express request object containing the authenticated user information
   * @param {Response} res - Express response object to send the generated backup codes
   * @param {NextFunction} next - Express next function for error handling
   * @returns {Promise<void>} Promise<void> - Resolves when backup codes are generated and sent
   */
  static async generateBackupCodes(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { id } = req.user as UserType;

      const backupCodes = await auth.generateBackupCodes(id, "tematId"); // FIXME: add a tenetId for the user
      res.status(HttpStatus.CREATED).json({ codes: backupCodes });
    } catch (error) {
      next(error);
    }
  }
  /**
   * Verifies a user's backup code for authentication.
   * If the code is valid, issues a new authentication token.
   *
   * @param {Request} req - The request object containing the user's ID and backup code.
   * @param {Response} res - The response object used to send the authentication token.
   * @param {NextFunction} next - The next middleware function to handle errors.
   * @returns {Promise<void>} A promise that resolves when the process is complete.
   *
   * @throws {Error} If an unexpected error occurs.
   */
  static async verifyBackupCode(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { id } = req.user as UserType;

      const verified = await auth.verifyBackupCode(
        id,
        "tanetid", // FIXME: add a tenetId for the user
        req.body.code as string
      );
      if (!verified) {
        res
          .status(HttpStatus.UNAUTHORIZED)
          .json({ message: "No backup codes found or Invaild code" });
        return;
      }
      const token = issueToken(req.user as UserType);
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
  static async forgotPassword(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { email } = req.body;

      // Find user by email
      const user = await User.findUnique({ where: { email } });
      if (!user) {
        res.status(400).json({ message: "User not found" });
        return;
      }

      // Generate a secure reset token
      const resetToken = crypto.randomBytes(32).toString("hex");
      const hashedToken = await bcrypt.hash(resetToken, 10);
      const expiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour expiry
      // Save token in the database
      await User.update({
        where: { email },
        data: { passwordResetToken: hashedToken, passwordResetExpires: expiry },
      });
      await auth.sendEmailForgotPassword(email, user.username, user.id);
    } catch (error) {
      next(error);
    }
  }
  static async restePassword(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    const { email, token, newPassword } = req.body as ResetPasswordData;
    try {
      // Find user by email
      const user = await User.findUnique({ where: { email } });
      if (!user || !user.passwordResetToken) {
        res.status(400).json({ message: "Invalid request" });
        return;
      }
      // Check token expiration
      if (user.passwordResetExpires && user.passwordResetExpires < new Date()) {
        res.status(400).json({ message: "Token expired" });
        return;
      }

      // Verify token
      const isValid = await bcrypt.compare(token, user.passwordResetToken);
      if (!isValid) {
        res.status(400).json({ message: "Invalid or expired token" });
        return;
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update user password and clear reset token
      await User.update({
        where: { email },
        data: {
          password: hashedPassword,
          passwordResetToken: null,
          passwordResetExpires: null,
        },
      });

      res.json({ message: "Password reset successful" });
    } catch (error) {
      next(error);
    }
  }
}
