import express from "express";
import cors from "cors";
import morgan from "morgan";
import AppRouter from "@/routes";
import { errorMiddleware } from "@/middlewares/error";

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev")); // Logs requests in the terminal
app.use("/api", AppRouter);

app.use(errorMiddleware);

export default app;
