import jwt from "jsonwebtoken";
import fs from "fs";
import { Request, Response, NextFunction } from "express";

const publickey = fs.readFileSync('public.pem', 'utf8');

import { IJwt } from "../express";


const verifyJWT = (req:Request, res: Response, next: NextFunction)=>{

    try {
        const accessToken = req.headers.authorization?.split(" ")[1];

        if(!accessToken){
            return res.status(401).json({message: "unauthorized"});
        }

        let decoded = <IJwt>jwt.verify(
            accessToken,
            publickey,
            {
                algorithms: ["ES256"]
            }
        ) 
                         
    req.user = decoded;

    next();

    } catch (error) {
        res.status(401).json({message: "unauthorized"});
    }


}

export default verifyJWT;