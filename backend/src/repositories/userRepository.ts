/* eslint-disable @typescript-eslint/no-explicit-any */
import { IUserRepository } from '../interface/IRepositoryInterface/IUserRepository';
import { AppError } from '../utils/appError';
import User from '../models/userModel';
import { IUser } from '../interface/common.interface';
import HTTP_statusCode from '../enums/httpStatusCode';

export class UserRepository implements IUserRepository {
  async getAllUsers(): Promise<IUser[]> {
    const users = await User.find();
    if (!users || users.length === 0) {
      throw new AppError('No users found', HTTP_statusCode.NotFound);
    }
    return users;
  }

  async findByEmail(email: string): Promise<IUser | null> {
    return User.findOne({ email });
  }

  async findById(userId: string): Promise<IUser | null> {
    return User.findById(userId);
  }

  async createUser(data: any): Promise<IUser> {
    const user = new User(data);
    return await user.save();
  }

  async updateUser(userId: string, updates: Partial<IUser>): Promise<IUser> {
    const user = await User.findByIdAndUpdate(userId, updates, {
      new: true,
      runValidators: true,
    });

    if (!user) {
      throw new AppError('User not found', HTTP_statusCode.NotFound);
    }

    return user;
  }

  async saveUser(userId: string, userData: IUser): Promise<IUser> {
    const user = await User.findByIdAndUpdate(userId, userData, {
      new: true,
      runValidators: true,
    });

    if (!user) {
      throw new AppError('User not found', HTTP_statusCode.NotFound);
    }

    return user;
  }
}

export const userRepository = new UserRepository();
