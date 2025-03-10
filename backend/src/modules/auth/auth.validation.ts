import { User } from "@/config/db";
import { z } from "zod";

export const registerSchema = z.object({
  body: z.object({
    username: z
      .string()
      .min(2, { message: "username must be at least 2 characters long" })
      .max(255, { message: "username must not exceed 255 characters" }),
    email: z
      .string()
      .email({ message: "Invalid email format" })
      .refine(
        async (email) => {
          const user = await User.findUnique({ where: { email } });
          return !user; // Return `true` if email is NOT taken
        },
        { message: "Email already exists" }
      ),
    password: z
      .string()
      .min(6, { message: "Password must be at least 6 characters long" })
      .max(32, { message: "Password must not exceed 32 characters" })
      .regex(/[A-Z]/, {
        message: "Password must contain at least one uppercase letter",
      })
      .regex(/[a-z]/, {
        message: "Password must contain at least one lowercase letter",
      })
      .regex(/\d/, { message: "Password must contain at least one number" })
      .regex(/[\W_]/, {
        message: "Password must contain at least one special character",
      }),
  }),
});

export const loginSchema = z.object({
  body: z.object({
    email: z
      .string()
      .email({ message: "Invalid email format" })
      .refine(
        async (email) => {
          const user = await User.findUnique({ where: { email } });
          return !!user; // Return `true` if the user exists
        },
        { message: "No account found with this email" }
      ),
    password: z
      .string()
      .min(6, { message: "Password must be at least 6 characters long" })
      .max(32, { message: "Password must not exceed 32 characters" }),
  }),
});
