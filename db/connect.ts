import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

const DbUrl = process.env.mongoURL;

const connectToDatabase = async (): Promise<void> => {
  try {
    mongoose.connect(DbUrl as string);

    console.log("successful connection to database ");
  } catch (error) {
    console.error(`connection to database failed. \n error occured : ${error}`);
    process.exit(1);
  }
};

export default connectToDatabase;
