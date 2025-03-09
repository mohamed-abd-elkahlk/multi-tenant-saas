import { HttpStatus } from "@/constants/httpStatus";
import { Request, Response, NextFunction } from "express";

/**
 * Global error-handling middleware for Express.
 *
 * @param {Error} err - The error object.
 * @param {Request} req - The Express request object.
 * @param {Response} res - The Express response object.
 * @param {NextFunction} next - The next middleware function.
 */
export function errorMiddleware(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction // eslint-disable-line @typescript-eslint/no-unused-vars
) {
  // Define a default status code and message
  const statusCode =
    res.statusCode === 200 ? HttpStatus.INTERNAL_SERVER_ERROR : res.statusCode; // Ensure proper error status

  // Check if in development mode
  const isDevelopment = process.env.NODE_ENV === "development";
  // if (isDevelopment) console.log(err);
  res.status(statusCode).json({
    success: false,
    message: err.message || "Internal Server Error",
    ...(isDevelopment && { stack: err.stack }), // Include stack trace only in development
  });
}
