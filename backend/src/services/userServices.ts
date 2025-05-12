import { IUserService } from '../interface/IServiceInterface/IUserServices';
import { IUserRepository } from '../interface/IRepositoryInterface/IUserRepository';
import { AppError } from '../utils/appError';
import { AuthResponse, IUser } from '../interface/common.interface';
import bcrypt from 'bcrypt';
import generateTokens from '../utils/jwtUtils';
import { Request, Response } from 'express';
import { generateOTP, sendOTP } from '../utils/otpUtils';
import HTTP_statusCode from '../enums/httpStatusCode';

export class UserService implements IUserService {
  constructor(private readonly userRepository: IUserRepository) {}

  async getProfile(userId: string): Promise<any> {
    const user = await this.userRepository.findById(userId);

    if (!user) {
      throw new AppError('User not found', HTTP_statusCode.NotFound);
    }

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      first_name: user.first_name,
      last_name: user.last_name,
      status: user.status,
    };
  }
}
