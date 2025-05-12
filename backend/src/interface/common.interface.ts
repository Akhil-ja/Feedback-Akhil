import { Document } from 'mongoose';
import { JwtPayload } from 'jsonwebtoken';
import { Request } from 'express';

export interface IUser extends Document {
  id: string;
  email: string;
  first_name?: string;
  last_name?: string;
  password: string;
  role: string;
  created_at: Date;
  edited_at: Date;
  status: string;
  resetPasswordOTP?: string;
  resetPasswordOTPExpires: Date;
}

export interface Tokens {
  accessToken: string;
  refreshToken: string;
}

export interface AuthResponse {
  user: IUser;
  tokens: Tokens;
}

export interface CustomRequest extends Request {
  user?: IUser;
}

export interface TokenPayload extends JwtPayload {
  id: string;
  role: string;
}
