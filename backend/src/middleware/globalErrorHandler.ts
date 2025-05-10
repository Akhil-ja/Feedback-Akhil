import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/appError';

const globalErrorHandler = (
  err: AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  err.statusCode = err.statusCode || 500;

  res.status(err.statusCode).json({
    status: err.statusCode >= 500 ? 'error' : 'fail',
    message: err.message,
  });
};

export default globalErrorHandler;
