import bcrypt from "bcrypt-ts";
import { User } from "@/config/db";
import { User as UserType } from "@prisma/client";
import transporter from "@/utils/email";
import { generateEmailVerificationToken } from "@/utils/jwt";

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
  /**
   * Sends a verification email to the user.
   *
   * @param {string} to - The recipient's email address
   * @param {string} username - The username of the recipient
   * @param {string} verificationLink - The verification link to be included in the email
   * @returns {Promise<void>}
   * @throws {Error} If there's an error sending the email
   */
  async sendVerificationEmail(
    to: string,
    username: string,
    token: string
  ): Promise<void> {
    try {
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject: "Email Verification",
        template: "emailVerification", // This should match my `emailVerification.hbs` file
        context: {
          username,
          verificationLink: `${process.env.FRONT_END_URL}/api/auth/email-verification?token=${token}`,
        },
      };

      await transporter.sendMail(mailOptions);
      console.log("Verification email sent successfully!");
    } catch (error) {
      console.error("Error sending email:", error);
      throw error; // Re-throw the error to handle it in the calling code
    }
  }

  async sendMFAEnabledEmail(to: string, username: string): Promise<void> {
    try {
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject: "Multi-Factor Authentication Enabled",
        template: "mfaEmailNotification", // This should match your `mfaEmailNotification.hbs` file
        context: {
          username,
          email: to,
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
}

/**
 * Sends an email verification link to the user.
 *
 * @param {string} to - Recipient's email address.
 * @param {string} username - The user's name.
 * @param {string} userId - The user's unique ID.
 * @returns {Promise<void>} Resolves when the email is sent successfully.
 */
export async function sendEmailVerification(
  to: string,
  username: string,
  userId: string
): Promise<void> {
  try {
    // Generate the verification token
    const token = generateEmailVerificationToken(userId, to);

    // Construct the email verification link
    const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

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
