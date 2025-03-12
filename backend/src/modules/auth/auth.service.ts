import bcrypt from "bcrypt-ts";
import { BackupCode, User } from "@/config/db";
import { User as UserType } from "@prisma/client";
import transporter from "@/utils/email";
import { generateEmailVerificationToken } from "@/utils/jwt";
import crypto from "crypto";

/**
 * Authentication service for handling user registration and login.
 */
export class AuthService {
  /**
   * Registers a new user by hashing the password and storing user data in the database.
   *
   * @param {string} username - The name of the user.
   * @param {string} email - The email of the user.
   * @param {string} password - The password of the user (will be hashed before storing).
   * @returns {Promise<UserType>} The created user object.
   * @throws {Error} If an error occurs while creating the user.
   */
  async register(
    username: string,
    email: string,
    password: string
  ): Promise<UserType> {
    // Hash the password
    const hash = await bcrypt.hash(password, 10);

    // Create a new user
    return await User.create({
      data: {
        email,
        username,
        password: hash,
      },
    });
  }

  /**
   * Logs in a user by verifying the email and password.
   *
   * @param {string} email - The email of the user.
   * @param {string} password - The password of the user.
   * @returns {Promise<UserType>} The authenticated user object.
   * @throws {Error} If the email or password is invalid.
   */
  async login(email: string, password: string): Promise<UserType> {
    // Find the user by email
    const user = await User.findUnique({
      where: {
        email,
      },
    });

    // If user not found
    if (!user) {
      throw new Error("Invalid email or password");
    }

    // Compare the password
    const isValid = await bcrypt.compare(password, user.password);

    // If password is invalid
    if (!isValid) {
      throw new Error("Invalid email or password");
    }

    // Return the user
    return user;
  }
  async sendMFAEnabledEmail(
    to: string,
    username: string,
    type: "Email" | "TOTP"
  ): Promise<void> {
    try {
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject: "Multi-Factor Authentication Enabled",
        template: "mfaEmailNotification", // This should match your `mfaEmailNotification.hbs` file
        context: {
          username,
          email: to,
          type,
          security_link: "https://example.com/security",
        },
      };

      await transporter.sendMail(mailOptions);
      console.log("MFA enabled notification email sent successfully!");
    } catch (error) {
      console.error("Error sending email:", error);
      throw error; // Re-throw the error to handle it in the calling code
    }
  }
  /**
   * Sends an email verification link to the user on reqister.
   *
   * @param {string} to - Recipient's email address.
   * @param {string} username - The user's name.
   * @param {string} userId - The user's unique ID.
   * @returns {Promise<void>} Resolves when the email is sent successfully.
   */
  async sendEmailVerification(
    to: string,
    username: string,
    userId: string
  ): Promise<void> {
    try {
      // Generate the verification token
      const token = generateEmailVerificationToken(userId, to);

      // Construct the email verification link
      const verificationLink = `${process.env.FRONT_END_URL}/api/verify-email?token=${token}`;

      // Email options
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject: "Verify Your Email Address",
        template: "emailVerification", // Corresponds to `emailVerification.hbs`
        context: {
          username,
          verificationLink,
        },
      };

      // Send email
      await transporter.sendMail(mailOptions);
      console.log("Email verification link sent successfully!");
    } catch (error) {
      console.error("Error sending email verification:", error);
      throw error; // Re-throw for handling in the calling code
    }
  }
  /**
   * Sends an email verification OTB to the user upon login.
   *
   * This function generates a verification token and sends an email
   * containing a verification OTB. The email is styled using the
   * `emailMFAVerification.hbs` template.
   *
   * @param {string} to - Recipient's email address.
   * @param {string} username - The user's name.
   * @param {number} emailOtp - The user's unique ID.
   * @returns {Promise<void>} Resolves when the email is sent successfully.
   * @throws {Error} Throws an error if email sending fails.
   *
   * @example
   * await sendEmailVerificationMFA("user@example.com", "JohnDoe", "12345");
   */
  async sendEmailMFA(
    to: string,
    username: string,
    emailOtp: number
  ): Promise<void> {
    try {
      // Email options
      const mailOptions = {
        from: process.env.EMAIL_USER, // Sender email address
        to, // Recipient email address
        subject: "Verify Your Email Address", // Email subject
        template: "emailMfaOTB", // Corresponds to `emailMFAVerification.hbs`
        context: {
          username, // Pass the username to the template
          emailOtp, // Pass the OTP to the template
          supportEmail: "support@example.com", // Support email for the footer
          appName: "MyApp", // Your app name for the footer
        },
      };

      // Send email
      await transporter.sendMail(mailOptions);
      console.log("Email verification link sent successfully!");
    } catch (error) {
      console.error("Error sending email verification:", error);
      throw error; // Re-throw for handling in the calling code
    }
  }
  async sendEmailForgotPassword(
    to: string,
    username: string,
    userId: string
  ): Promise<void> {
    try {
      // Generate the verification token
      const token = generateEmailVerificationToken(userId, to);

      // Construct the password reset link
      const resetLink = `${process.env.FRONT_END_URL}/reset-password?token=${token}`;

      // Email options
      const mailOptions = {
        from: process.env.EMAIL_USER, // Sender email address
        to, // Recipient email address
        subject: "Password Reset Request", // Email subject
        template: "forgotPassword", // Corresponds to `forgotPassword.hbs`
        context: {
          username, // Pass the username to the template
          resetLink, // Pass the reset link to the template
          year: new Date().getFullYear(), // Current year for the footer
          supportEmail: "support@example.com", // Support email for the footer
          appName: "MyApp", // Your app name for the footer
        },
      };

      // Send email
      await transporter.sendMail(mailOptions);
      console.log("Password reset email sent successfully!");
    } catch (error) {
      console.error("Error sending password reset email:", error);
      throw error; // Re-throw for handling in the calling code
    }
  }
  async sendEmailVerificationMFA(
    to: string,
    username: string,
    userId: string
  ): Promise<void> {
    try {
      // Generate the verification token
      const token = generateEmailVerificationToken(userId, to);

      // Construct the email verification link
      const verificationLink = `${process.env.FRONT_END_URL}/api/verify-email?token=${token}`;

      // Email options
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject: "Verify Your Email Address",
        template: "emailMFAVerification", // Corresponds to `emailMFAVerification.hbs`
        context: {
          username,
          verificationLink,
          year: new Date().getFullYear(),
        },
      };

      // Send email
      await transporter.sendMail(mailOptions);
      console.log("Email verification link sent successfully!");
    } catch (error) {
      console.error("Error sending email verification:", error);
      throw error; // Re-throw for handling in the calling code
    }
  }
  /**
   * Generates and stores a set of one-time-use backup codes for a user in a multi-tenant system.
   *
   * @param {string} userId - The unique identifier of the user.
   * @param {string} tenantId - The unique identifier of the tenant.
   * @returns {Promise<string[]>} A promise that resolves to an array of raw backup codes (to be saved by the user).
   * @throws {Error} If there is an issue with database operations.
   */
  async generateBackupCodes(
    userId: string,
    tenantId: string
  ): Promise<string[]> {
    // Generate 10 random codes
    const rawCodes = Array.from({ length: 10 }, () =>
      crypto.randomBytes(4).toString("hex")
    );

    // Hash the codes before storing them
    const hashedCodes = await Promise.all(
      rawCodes.map(async (code) => await bcrypt.hash(code, 10))
    );

    // Store in DB
    await BackupCode.upsert({
      where: { userId },
      update: { codes: hashedCodes },
      create: {
        userId,
        tenantId,
        codes: hashedCodes,
      },
    });

    return rawCodes; // Return raw codes for the user to save
  }
  /**
   * Verifies a backup code provided by the user and invalidates it upon successful use.
   *
   * @param {string} userId - The unique identifier of the user.
   * @param {string} tenantId - The unique identifier of the tenant.
   * @param {string} code - The backup code entered by the user.
   * @returns {Promise<boolean>} A promise that resolves to `true` if the code is valid, otherwise throws an error.
   * @throws {Error} If no backup codes exist or the provided code is invalid.
   */
  async verifyBackupCode(
    userId: string,
    tenantId: string,
    code: string
  ): Promise<boolean> {
    const backupRecord = await BackupCode.findUnique({ where: { userId } });
    if (!backupRecord || !backupRecord.codes) return false;

    const codes = backupRecord.codes as string[];
    // Check if the code matches any stored hash
    for (const hashedCode of codes) {
      if (await bcrypt.compare(code, hashedCode)) {
        // Remove used code
        await BackupCode.update({
          where: { userId, tenantId },
          data: {
            codes: codes.filter((c: string) => c !== hashedCode),
          },
        });
        return true; // Valid backup code
      }
    }

    return false;
  }
}
