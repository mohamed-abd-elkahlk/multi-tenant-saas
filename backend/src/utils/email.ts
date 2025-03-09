import nodemailer from "nodemailer";
import hbs from "nodemailer-express-handlebars";
import path from "path";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER, // Your email
    pass: process.env.EMAIL_PASS, // Your app password
  },
});

// Use handlebars with Nodemailer
transporter.use(
  "compile",
  hbs({
    viewEngine: {
      extname: ".hbs",
      layoutsDir: path.resolve(__dirname, "../views"), // Add layoutsDir
      partialsDir: path.resolve(__dirname, "../views"),
    },
    viewPath: path.resolve(__dirname, "../views"),

    extName: ".hbs",
  })
);

export default transporter;
