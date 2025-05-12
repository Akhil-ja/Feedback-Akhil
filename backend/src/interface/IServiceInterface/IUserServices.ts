import { Request, Response } from 'express';
import { IUser, AuthResponse } from '../common.interface';

export interface IUserService {
  getProfile(userId: string): Promise<any>;
}
