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
router.get("/verify-email", AuthController.emailVerification);
router.use(
  passport.authenticate("jwt", {
    session: false,
  })
);
router.post("/logout", AuthController.logout);
// FIXME: this routes not tested
router.post("/forgot-password", AuthController.forgotPassword);
router.post("/reset-password", AuthController.restePassword);
router.post("/backup-code", AuthController.generateBackupCodes);
router.post("/verify-backup-code", AuthController.verifyBackupCode);
router.post("/mfaenable", AuthController.enableMFA);

export default router;
