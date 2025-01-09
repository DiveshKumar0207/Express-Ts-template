import express from "express";
const router = express.Router();

import { query, body, param } from "express-validator";

import {
  resetPassword,
  sendResetPasswordMail,
} from "../controllers/resetPassword";

router.post(
  "/auth/reset-password/send-otp",
  [
    body("email")
      .trim()
      .isEmail()
      .normalizeEmail()
      .withMessage("Enter valid email"),
  ],
  sendResetPasswordMail
);

router.post(
  "/auth/reset-password/:userid/:token",
  [
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
    body("confirm-password")
      .trim()
      .custom((value, { req }) => {
        if (value !== req.body.password) {
          throw new Error("password dont match");
        }
        return true;
      }),
    param("userid").trim().escape(),
    param("token").trim().escape(),
  ],
  resetPassword
);

export default router;
