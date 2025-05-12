import { ISharedService } from '../interface/IServiceInterface/ISharedServices';
import { Request, Response } from 'express';
import generateTokens from '../utils/jwtUtils';
import { AuthResponse } from '../interface/common.interface';
import { IUserRepository } from '../interface/IRepositoryInterface/IUserRepository';
import { AppError } from '../utils/appError';
import { verifyPassword, hashPassword } from '../utils/passwordUtils';
import { IUser } from '../interface/common.interface';
import { generateOTP, sendOTP } from '../utils/otpUtils';
import HTTP_statusCode from '../enums/httpStatusCode';

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
      throw new AppError('Email not registered', HTTP_statusCode.NotFound);
    }

    if (role == 'admin') {
      throw new AppError('User is not authorized', HTTP_statusCode.NoAccess);
    }

    if (user.status === 'blocked') {
      throw new AppError('User is blocked', HTTP_statusCode.NoAccess);
    }

    const isPasswordValid = verifyPassword(password, user.password);

    if (!isPasswordValid) {
      throw new AppError('Incorrect password', HTTP_statusCode.Unauthorized);
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
      throw new AppError('Email not registered', HTTP_statusCode.NotFound);
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
      throw new AppError('Email not registered', HTTP_statusCode.NotFound);
    }

    if (user.role == 'admin') {
      throw new AppError('User is not authorized', HTTP_statusCode.NoAccess);
    }

    if (user.status === 'blocked') {
      throw new AppError('User is blocked', HTTP_statusCode.NoAccess);
    }

    const storedOTP = user?.resetPasswordOTP;

    if (!storedOTP) {
      throw new AppError('No OTP found', HTTP_statusCode.BadRequest);
    }

    if (Date.now() > user.resetPasswordOTPExpires.getTime()) {
      throw new AppError('OTP expired', HTTP_statusCode.BadRequest);
    }

    if (otp !== storedOTP) {
      console.log('OTP mismatch. Provided:', otp, 'Stored:', storedOTP);
      throw new AppError('Invalid OTP', HTTP_statusCode.BadRequest);
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
      throw new AppError('User not found', HTTP_statusCode.NotFound);
    }

    const { oldPassword, newPassword } = updates;

    if (!oldPassword || !newPassword) {
      throw new AppError(
        'Both old and new passwords are required',
        HTTP_statusCode.BadRequest
      );
    }

    if (oldPassword === newPassword) {
      throw new AppError(
        'New password must be different from the old password',
        HTTP_statusCode.BadRequest
      );
    }

    const isPasswordValid = verifyPassword(oldPassword, user.password);
    if (!isPasswordValid) {
      throw new AppError(
        'Current password is incorrect',
        HTTP_statusCode.Unauthorized
      );
    }

    const hashedPassword = hashPassword(newPassword);

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
