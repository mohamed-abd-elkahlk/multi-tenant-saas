import express from "express";
import { AuthController } from "./auth.controller";
import { validateRequest } from "@/middlewares/validation";
import { loginSchema, registerSchema } from "./auth.validation";
import passport from "passport";
const router = express.Router();

router.post(
  "/register",
  validateRequest(registerSchema),
  AuthController.register
);
router.post("/login", validateRequest(loginSchema), AuthController.login);
router.get("/email-verification", AuthController.emailVerification);
router.use(
  passport.authenticate("jwt", {
    session: false,
  })
);
router.post("/logout", AuthController.logout);
router.post("/mfaenable", AuthController.enableMFA);

export default router;
