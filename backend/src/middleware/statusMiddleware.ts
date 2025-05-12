/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/appError';
import HTTP_statusCode from '../enums/httpStatusCode';

const checkBlockedUser = async (
  req: any,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const user = req.user;

    if (user.status === 'blocked') {
      console.log('User is blocked, sending 403');
      res.clearCookie('user');
      return next(
        new AppError('Your account has been blocked', HTTP_statusCode.NoAccess)
      );
    }
    next();
  } catch (error) {
    console.error('Error fetching users:', error);
    next(
      new AppError(
        'Unknown error occurred',
        HTTP_statusCode.InternalServerError
      )
    );
  }
};

export { checkBlockedUser };
