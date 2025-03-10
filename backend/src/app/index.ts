import express from "express";
import cors from "cors";
import morgan from "morgan";
import AppRouter from "@/routes";
import { errorMiddleware } from "@/middlewares/error";
import passport from "@/config/passport";
import path from "path";

const app = express();
// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, "../public")));

app.use(express.json());
app.use(cors());
app.use(morgan("dev")); // Logs requests in the terminal
app.use(passport.initialize());
app.use("/api", AppRouter);
app.get("/", (req, res) => {
  res.send("Welcome to the API");
});
app.use(errorMiddleware);

export default app;
