import * as crypto from "crypto";

import { Response, Request, Errback, NextFunction } from "express";
import { matchedData, validationResult } from "express-validator";
import userModel from "../db/models/user.model";
import resetTokenModel from "../db/models/resetToken.model";
import { sendPasswordResetEmailFunc } from "../utils/sendEmail";
import { ObjectId } from "mongoose";
import { hashPassword } from "../utils/hashPassword";

// Sends OTP to an email controller on route /api/auth/reset-password/send-otp/
const sendResetPasswordMail = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // validation err
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ erros: errors.array() });
  }
  //  get validated data
  const validatedData = matchedData(req);

  try {
    const { email } = validatedData;

    const isEmailExist = await userModel.findOne({ email });

    if (!isEmailExist) {
      res.status(404).send({ error: "Email does not exist" });
    }

    const userid = isEmailExist?._id as ObjectId;

    const existingToken = await resetTokenModel.findOne({ userid });

    const token = crypto.randomBytes(16).toString("hex"); //generates new token

    const link = `${process.env.BASE_URL}/reset-password/${userid}/${token}`;

    if (existingToken) {
      // Check if 1 minute has passed since the last request
      const timeSinceLastRequest =
        Date.now() - existingToken.createdAt.getTime();
      if (timeSinceLastRequest < 60000) {
        return res.status(429).json({
          message: "Please wait 1 minute before requesting another reset link",
        });
      }

      existingToken.token = token; //updates token
      existingToken.createdAt = new Date(Date.now()); //expires the existing otp
      await existingToken.save();
    } else {
      const newToken = new resetTokenModel({
        userid,
        token,
      }); //create new document if already not exists
      await newToken.save(); //saves otp in database
    }

    await sendPasswordResetEmailFunc(email, link); //sends otp to mail

    res
      .status(201)
      .json({ message: "Reset link sent to your email", link: link });
  } catch (err) {
    // Pass the error to the error handling middleware
    next(err);
  }
};

// Reset the password controller on route /api//auth/reset-password/:userid/:token
const resetPassword = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // validation err
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ erros: errors.array() });
  }
  //  get validated data
  const validatedData = matchedData(req);

  try {
    const { password, token, userid } = validatedData;

    const isTokenExist = await resetTokenModel.findOne({ userid, token }); //will check document in database based token and userid. if not found means expired or pampered. Check resettoken.model.ts

    if (!isTokenExist) {
      res.status(404).json({ message: "Invalid or expired token." });
    }

    const { hash, salt } = hashPassword(password);

    const updatedUserPass = await userModel.findOneAndUpdate(
      { _id: userid },
      { password: hash, salt },
      { new: true }
    );

    if (!updatedUserPass) {
      res.status(404).json({ message: "Unauthorized" });
    }

    await updatedUserPass?.save();

    res.status(200).json({ message: "Password updated successfully." });
  } catch (error) {
    next(error);
  }
};

export { sendResetPasswordMail, resetPassword };
