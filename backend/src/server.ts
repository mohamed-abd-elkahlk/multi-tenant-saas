// Load env variables
import app from "./app";
import "./config/env";
import allRoutes from "express-list-endpoints";

const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`🚀 Server running http://localhost:${PORT} \n`);
  const routes = allRoutes(app);
  console.log("🚀 Available routes: \n");

  for (let i = 0; i < routes.length; i++) {
    console.log(`${routes[i].methods} ${routes[i].path} \n`);
  }
});
