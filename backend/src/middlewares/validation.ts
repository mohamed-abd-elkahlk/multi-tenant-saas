import { Request, Response, NextFunction } from "express";
import { AnyZodObject, ZodError } from "zod";

/**
 * Middleware function to validate request using Zod schema
 * @param schema - Zod schema to validate against
 * @returns Express middleware function that validates request body, query, and params
 * @throws {ZodError} - If validation fails
 *
 * @example
 * const userSchema = z.object({
 *   body: z.object({
 *     name: z.string(),
 *     email: z.string().email()
 *   })
 * });
 *
 * app.post('/users', validateRequest(userSchema), (req, res) => {
 *   // Handle valid request
 * });
 */
export const validateRequest =
  (schema: AnyZodObject) =>
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate the request body, query, or params
      await schema.parseAsync({
        body: req.body,
        query: req.query,
        params: req.params,
      });
      next(); // Proceed to the next middleware or route handler
    } catch (error) {
      if (error instanceof ZodError) {
        // Format validation errors
        const formattedErrors = error.errors.map((err) => ({
          message: err.message,
          path: err.path.join("."), // Join path array with dots (e.g., "body.name")
        }));

        // Send formatted errors in the response
        res
          .status(400)
          .json({
            message: "Validation failed",
            errors: formattedErrors,
          })
          .end();
        return;
      }
      // Handle other errors
      next();
    }
  };
