import mongoose from "mongoose";

// Define an interface for the User document
export interface Itoken extends mongoose.Document {
  userid: mongoose.ObjectId;
  token: string;
  createdAt: Date;
}

// Creating user schema
const otpSchema = new mongoose.Schema<Itoken>({
  userid: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "user",
    required: true,
  },
  token: {
    type: String,
    required: true,
    trim: true,
  },
  createdAt: {
    type: Date,
    required: true,
    default: Date.now,
    index: { expires: "10m" },
  },
});

// created user model
const resetTokenModel = mongoose.model<Itoken>("resetToken", otpSchema);

export default resetTokenModel;
