import bcrypt from "bcrypt-ts";
import { User } from "@/config/db";
import { User as UserType } from "@prisma/client";

/**
 * Authentication service for handling user registration and login.
 */
export class AuthService {
  /**
   * Registers a new user by hashing the password and storing user data in the database.
   *
   * @param {string} name - The name of the user.
   * @param {string} email - The email of the user.
   * @param {string} password - The password of the user (will be hashed before storing).
   * @returns {Promise<UserType>} The created user object.
   * @throws {Error} If an error occurs while creating the user.
   */
  async register(
    name: string,
    email: string,
    password: string
  ): Promise<UserType> {
    // Hash the password
    const hash = await bcrypt.hash(password, 10);

    // Create a new user
    return await User.create({
      data: {
        email,
        name,
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
}
