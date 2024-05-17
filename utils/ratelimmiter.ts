import { Request, Response, NextFunction } from "express";
import { RateLimiterMemory } from "rate-limiter-flexible";

const rateLimiter = new RateLimiterMemory({
  points: 5, // Number of points
  duration: 1, // Per second
});

export const rateLimiterMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  rateLimiter
    .consume(req.ip as string)
    .then(() => {
      // Request allowed, continue to the next middleware or route handler
      next();
    })
    .catch(() => {
      // Request denied due to rate limiting
      // logCustomMessage("Too Many Requests: rateLimiter ");
      res.status(429).send("Too Many Requests");
    });
};
