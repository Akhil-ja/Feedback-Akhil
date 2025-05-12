/* eslint-disable @typescript-eslint/no-explicit-any */
import HTTP_statusCode from '../enums/httpStatusCode';
import { IUserService } from '../interface/IServiceInterface/IUserServices';
import { AppError } from '../utils/appError';
import { NextFunction, Request, Response } from 'express';

export class UserController {
  constructor(private readonly UserService: IUserService) {}

  fetchUserProfile = async (
    req: any,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const userId = req.user?.id;

      if (!userId) {
        throw new AppError(
          'Authentication required',
          HTTP_statusCode.Unauthorized
        );
      }

      const userProfile = await this.UserService.getProfile(userId);

      res.status(200).json({
        message: 'Profile fetched successfully',
        user: userProfile,
      });
    } catch (error) {
      console.error('Error fetching profile:', error);
      next(
        error instanceof AppError
          ? error
          : new AppError(
              'Profile fetch failed',
              HTTP_statusCode.InternalServerError
            )
      );
    }
  };
}
