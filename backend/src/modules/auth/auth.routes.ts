import express from "express";
import { AuthController } from "./auth.controller";
import { validateRequest } from "@/middlewares/validation";
import { reqisterSchema } from "./auth.validation";
const router = express.Router();

// Correct the issue by wrapping async functions properly

router.post(
  "/register",
  validateRequest(reqisterSchema),
  AuthController.register
);

router.post("/login", AuthController.login);

export default router;
