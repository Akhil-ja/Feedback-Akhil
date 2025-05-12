import { IUser } from '../common.interface';
import { AuthResponse } from '../common.interface';
import { Request, Response } from 'express';

export interface ISharedService {
  signIn(
    email: string,
    password: string,
    res: Response,
    req: Request
  ): Promise<AuthResponse>;

  sendOTPForForgotPassword(email: string, res: Response): Promise<void>;

  verifyOTPAndSignIn(
    email: string,
    otp: string,
    res: Response,
    req: Request
  ): Promise<AuthResponse>;

  changePassword(
    userId: string,
    updates: {
      oldPassword?: string;
      newPassword?: string;
    }
  ): Promise<IUser>;

  logout(res: any): Promise<void>;
}
