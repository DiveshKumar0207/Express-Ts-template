import express from "express";
const router = express.Router();

import { query, body } from "express-validator";

import verifyJWT from "../middlewares/verifyJWT";

import { login, signUp } from "../controllers/authController";

router.post(
  "/auth/signup",
  [
    body("firstname").trim().isLength({ min: 3 }).escape(),
    body("lastname").trim().isLength({ min: 3 }).escape(),
    body("email")
      .trim()
      .isEmail()
      .normalizeEmail()
      .withMessage("Enter valid email"),
    body("password")
      .trim()
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long")
      .matches(/[a-z]/)
      .withMessage("Password must contain at least one lowercase letter")
      .matches(/[A-Z]/)
      .withMessage("Password must contain at least one uppercase letter")
      .matches(/\d/)
      .withMessage("Password must contain at least one digit")
      .matches(/[!@#$%^&*()_+-=]/)
      .withMessage("Password must contain at least one special character")
      .escape(),
  ],
  signUp
);

router.post(
  "/auth/login",
  [
    body("email")
      .trim()
      .isEmail()
      .normalizeEmail()
      .withMessage("Enter valid email"),
    body("password").trim().isLength({ min: 8 }).escape(),
  ],
  login
);

export default router;
