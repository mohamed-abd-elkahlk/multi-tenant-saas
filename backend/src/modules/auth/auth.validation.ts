import { User } from "@/config/db";
import { z } from "zod";

export const reqisterSchema = z.object({
  body: z.object({
    name: z.string().min(2).max(255),
    email: z
      .string()
      .email()
      .refine(
        async (email) => {
          // Check if the email already exists
          const user = await User.findUnique({ where: { email } });
          if (!user) {
            return false;
          }
        },
        { message: "Email already exists" }
      ),
    password: z.string().min(6).max(255),
  }),
});
