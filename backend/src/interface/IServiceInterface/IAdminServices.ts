import { IUser } from '../common.interface';
import { AuthResponse } from '../common.interface';
import { Request, Response } from 'express';

export interface IAdminService {
  adminSignIn(
    email: string,
    password: string,
    res: Response,
    req: Request
  ): Promise<AuthResponse>;

  createUser(userData: {
    email: string;
    password: string;
    role: string;
    firstName?: string;
    lastName?: string;
  }): Promise<Partial<IUser>>;

  Adminlogout(res: any): Promise<void>;
}
