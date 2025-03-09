// import AuthRouter from "@/modules/auth/auth.routes";
import AuthRouter from "./modules/auth/auth.routes";
import express from "express";

const router = express.Router();

router.use("/auth", AuthRouter);
export default router;
