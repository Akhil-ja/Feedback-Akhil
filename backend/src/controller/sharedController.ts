/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextFunction, Response, Request } from 'express';
import { AppError } from '../utils/appError';
import { ISharedService } from '../interface/IServiceInterface/ISharedServices';

export class SharedController {
  constructor(private readonly sharedService: ISharedService) {}

  signIn = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const { email, password } = req.body;

    try {
      const { user, tokens } = await this.sharedService.signIn(
        email,
        password,
        res,
        req
      );
      res.status(200).json({
        message: 'Sign in successful',
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          first_name: user.first_name,
          last_name: user.last_name,
        },
        tokens,
      });
    } catch (error) {
      console.error('Error during Sign-in:', error);
      next(
        error instanceof AppError
          ? error
          : new AppError('Failed to signin', 400)
      );
    }
  };

  forgotPassword = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const { email } = req.body;

    try {
      await this.sharedService.sendOTPForForgotPassword(email, res);
      res.status(200).json({
        message: 'OTP sent for verification',
      });
    } catch (error) {
      console.error('Error during OTP resend:', error);
      next(
        error instanceof AppError
          ? error
          : new AppError('Failed to resend OTP', 400)
      );
    }
  };

  verifyForgotOTP = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const { email, otp } = req.body;

    try {
      const { user, tokens } = await this.sharedService.verifyOTPAndSignIn(
        email,
        otp,
        res,
        req
      );
      res.status(200).json({
        message: 'Sign in successful',
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          first_name: user.first_name,
          last_name: user.last_name,
        },
        tokens,
      });
    } catch (error) {
      console.error('Error during OTP verification:', error);
      next(
        error instanceof AppError
          ? error
          : new AppError('Failed to verify OTP', 400)
      );
    }
  };

  changePassword = async (
    req: any,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const userId = req.user?.id;

      if (!userId) {
        throw new AppError('Authentication required', 401);
      }

      const { oldPassword, newPassword } = req.body;

      if (!oldPassword || !newPassword) {
        throw new AppError('Both old and new passwords are required', 400);
      }

      const updatedUser = await this.sharedService.changePassword(userId, {
        oldPassword,
        newPassword,
      });

      res.status(200).json({
        message: 'Password updated successfully',
        user: {
          id: updatedUser.id,
          email: updatedUser.email,
          role: updatedUser.role,
          first_name: updatedUser.first_name,
          last_name: updatedUser.last_name,
        },
      });
    } catch (error) {
      console.error('Error changing password:', error);
      next(
        error instanceof AppError
          ? error
          : new AppError('Password update failed', 500)
      );
    }
  };

  logout = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      await this.sharedService.logout(res);
      res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
      console.error('Error during logout:', error);
      next(
        error instanceof AppError ? error : new AppError('Logout failed', 500)
      );
    }
  };
}
