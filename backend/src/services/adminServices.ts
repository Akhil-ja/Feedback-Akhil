import { IUserRepository } from '../interface/IRepositoryInterface/IUserRepository';
import { IAdminService } from '../interface/IServiceInterface/IAdminServices';
import { IUser } from '../interface/common.interface';
import { AppError } from '../utils/appError';
import bcrypt from 'bcrypt';
import { AuthResponse } from '../interface/common.interface';
import generateTokens from '../utils/jwtUtils';
import { Request, Response } from 'express';

export class AdminService implements IAdminService {
  constructor(private readonly userRepository: IUserRepository) {}

  async adminSignIn(
    email: string,
    password: string,
    res: Response,
    req: Request
  ): Promise<AuthResponse> {
    const user = await this.userRepository.findByEmail(email);

    if (!user) {
      throw new AppError('Email not registered', 404);
    }

    if (user.role !== 'admin') {
      throw new AppError('Admin is not authorized', 403);
    }

    if (user.status === 'blocked') {
      throw new AppError('User is blocked', 403);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new AppError('Incorrect password', 401);
    }

    const tokens = generateTokens(user.id, user.role);

    res.cookie('admin_accessToken', tokens.accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 15 * 60 * 1000,
      sameSite: 'none',
    });

    res.cookie('admin_refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'none',
    });

    return { user, tokens };
  }

  async createUser(userData: {
    email: string;
    password: string;
    role: string;
    firstName?: string;
    lastName?: string;
  }): Promise<Partial<IUser>> {
    const existingUser = await this.userRepository.findByEmail(userData.email);

    if (existingUser) {
      throw new AppError('Email already registered', 409);
    }

    const validRoles = ['employee', 'manager'];
    if (!validRoles.includes(userData.role)) {
      throw new AppError('Invalid role specified', 400);
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(userData.password, saltRounds);

    const newUser = await this.userRepository.createUser({
      email: userData.email,
      password: hashedPassword,
      role: userData.role,
      first_name: userData.firstName,
      last_name: userData.lastName,
      status: 'active',
    });

    return {
      id: newUser.id,
      email: newUser.email,
      role: newUser.role,
      first_name: newUser.first_name,
      last_name: newUser.last_name,
      status: newUser.status,
      created_at: newUser.created_at,
    };
  }

  async Adminlogout(res: any): Promise<void> {
    console.log(res.user);

    console.log('Logging out...');

    res.clearCookie('admin_accessToken', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
    });

    res.clearCookie('admin_refreshToken', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
    });
  }
}
