import express, { NextFunction, Request, Response } from "express";
import dotenv from "dotenv";
import morgan from "morgan";
import hpp from "hpp";
import helmet from "helmet";
import cors from "cors";
import compression from "compression";

import connectToDatabase from "./db/connect";
import router from "./routes/route";
import { rateLimiterMiddleware } from "./utils/ratelimmiter";

dotenv.config();
const app = express();
connectToDatabase();

// Middleware that allows Express to parse through both JSON and x-www-form-urlencoded request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: false }));


// Enable CORS with specified options
// app.use(cors(corsOptions));
app.use(cors());

// Enable Helmet middleware for secure HTTP headers
app.use(helmet());

// Enable HPP middleware to prevent HTTP Parameter Pollution attacks
app.use(hpp());

// Use rate limiter middleware
app.use(rateLimiterMiddleware);

// Morgan middleware for logging requests to the console
app.use(morgan("dev"));

// Use compression middleware // compress the response based on the client's capabilities
app.use(compression());


const PORT = process.env.PORT || 8081;


app.use("/api/", router);

// 404 Route Handling
app.use((req: Request, res: Response, next: NextFunction) => {
    res.status(404).json({ error: 'Not Found' });
  });
  
// Global Error Handling Middleware
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error(err); // Log the error
    res.status(500).json({ error: 'Internal Server Error' });
});
  

app.listen(PORT, ()=>{
    console.log(`server running on :  http://localhost:${PORT}`)
})