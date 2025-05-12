import { ISharedService } from '../interface/IServiceInterface/ISharedServices';
import { Request, Response } from 'express';
import generateTokens from '../utils/jwtUtils';
import { AuthResponse } from '../interface/common.interface';
import { IUserRepository } from '../interface/IRepositoryInterface/IUserRepository';
import { AppError } from '../utils/appError';
import { verifyPassword, hashPassword } from '../utils/passwordUtils';
import { IUser } from '../interface/common.interface';
import { generateOTP, sendOTP } from '../utils/otpUtils';

export class SharedService implements ISharedService {
  constructor(private readonly userRepository: IUserRepository) {}

  async signIn(
    email: string,
    password: string,
    res: Response,
    req: Request
  ): Promise<AuthResponse> {
    const user = await this.userRepository.findByEmail(email);
    const role = user?.role;

    if (!user) {
      throw new AppError('Email not registered', 404);
    }

    if (role == 'admin') {
      throw new AppError('User is not authorized', 403);
    }

    if (user.status === 'blocked') {
      throw new AppError('User is blocked', 403);
    }

    const isPasswordValid = verifyPassword(password, user.password);

    if (!isPasswordValid) {
      throw new AppError('Incorrect password', 401);
    }

    const tokens = generateTokens(user.id, user.role);

    res.cookie('user_accessToken', tokens.accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 15 * 60 * 1000,
      sameSite: 'none',
    });

    res.cookie('user_refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'none',
    });

    return { user, tokens };
  }

  async sendOTPForForgotPassword(email: string, res: Response): Promise<void> {
    const user = await this.userRepository.findByEmail(email);

    if (!user) {
      throw new AppError('Email not registered', 404);
    }

    const otp = generateOTP();
    const otpExpiration = new Date(Date.now() + 5 * 60 * 1000);

    user.resetPasswordOTP = otp;
    user.resetPasswordOTPExpires = otpExpiration;
    await this.userRepository.saveUser(user.id, user);

    await sendOTP(email, otp);
    console.log(otp, 'is the otp');
  }

  async verifyOTPAndSignIn(
    email: string,
    otp: string,
    res: Response,
    req: Request
  ): Promise<AuthResponse> {
    const user = await this.userRepository.findByEmail(email);

    if (!user) {
      throw new AppError('Email not registered', 404);
    }

    if (user.role == 'admin') {
      throw new AppError('User is not authorized', 403);
    }

    if (user.status === 'blocked') {
      throw new AppError('User is blocked', 403);
    }

    const storedOTP = user?.resetPasswordOTP;

    if (!storedOTP) {
      throw new AppError('No OTP found', 400);
    }

    if (Date.now() > user.resetPasswordOTPExpires.getTime()) {
      throw new AppError('OTP expired', 400);
    }

    if (otp !== storedOTP) {
      console.log('OTP mismatch. Provided:', otp, 'Stored:', storedOTP);
      throw new AppError('Invalid OTP', 400);
    }

    user.resetPasswordOTP = undefined;
    user.resetPasswordOTPExpires = new Date(0);
    await this.userRepository.saveUser(user.id, user);

    const tokens = generateTokens(user.id, user.role);

    res.cookie('user_accessToken', tokens.accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 15 * 60 * 1000,
      sameSite: 'none',
    });

    res.cookie('user_refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'none',
    });

    return {
      user,
      tokens,
    };
  }

  async changePassword(
    userId: string,
    updates: {
      oldPassword?: string;
      newPassword?: string;
    }
  ): Promise<IUser> {
    const user = await this.userRepository.findById(userId);

    if (!user) {
      throw new AppError('User not found', 404);
    }

    const { oldPassword, newPassword } = updates;

    if (!oldPassword || !newPassword) {
      throw new AppError('Both old and new passwords are required', 400);
    }

    if (oldPassword === newPassword) {
      throw new AppError(
        'New password must be different from the old password',
        400
      );
    }

    const isPasswordValid = await verifyPassword(oldPassword, user.password); // make sure this is `await` if `verifyPassword` is async

    if (!isPasswordValid) {
      throw new AppError('Current password is incorrect', 401);
    }

    const hashedPassword = await hashPassword(newPassword); // make sure this is `await` if `hashPassword` is async

    user.password = hashedPassword;
    user.edited_at = new Date();

    await this.userRepository.updateUser(userId, { password: hashedPassword });

    return user;
  }

  async logout(res: any): Promise<void> {
    console.log(res.user);

    console.log('Logging out...');

    res.clearCookie('user_accessToken', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
    });

    res.clearCookie('user_refreshToken', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
    });
  }
}
