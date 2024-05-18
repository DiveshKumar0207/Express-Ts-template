import { Request } from 'express';

// Interface for JWT payload, used in verifyjwt middleware
interface IJwt extends  jwt.JwtPayload {
    userId : ObjectId,            //can add userRole here if required 
}

// Globally chnage "Request" type in server
declare module 'express' {
  interface Request {
    user?: IJwt; // Replace `any` with the appropriate type for your user object
  }
}