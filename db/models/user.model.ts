import { NextFunction } from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs"

// Define an interface for the User document
export interface IUser extends mongoose.Document{
    name: string;
    email: string;
    password: string;
    isActive : Boolean;
    createdAt: Date;
    updatedAt: Date;
}


// Creating user schema
const userSchema  = new mongoose.Schema<IUser>({
    name : {
        type: String,
        required: true,
        trim: true
    },
    email : {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password : {
        type: String,
        required : true,
        trim: true
    },
    isActive: { 
        type: Boolean,
        default: false
    },
}, 
{
    timestamps: true,
}
);

// Middleware for hashing our password
userSchema.pre<IUser>('save', async function(next){
    const saltRound = 12;

    if(this.isModified('password')){
        try {
            this.password = await bcrypt.hash(this.password, saltRound)
        } catch (error) {
            next(new Error("hash failed"));
        }
    }

    next();
})

// created user model
const userModel = mongoose.model<IUser>('User', userSchema);

export default userModel;

