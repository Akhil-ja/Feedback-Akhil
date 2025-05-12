import jwt, { JwtPayload } from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import User from '../models/userModel';
import { IUser } from '../interface/common.interface';
import generateTokens from '../utils/jwtUtils';

interface CustomRequest extends Request {
  user?: IUser;
}

interface TokenPayload extends JwtPayload {
  id: string;
  role: string;
}

const adminProtect = async (
  req: CustomRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const accessToken = req.cookies?.admin_accessToken;
    const refreshToken = req.cookies?.admin_refreshToken;

    if (!accessToken) {
      if (refreshToken) {
        res.status(401).json({
          message: 'Access token expired',
          shouldRefresh: true,
        });
        return;
      }
      res.status(401).json({
        message: 'Not authorized, please login',
        shouldReLogin: true,
      });
      return;
    }

    if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
      throw new Error('JWT_SECRET or REFRESH_TOKEN_SECRET is not defined');
    }

    try {
      const decoded = jwt.verify(
        accessToken,
        process.env.JWT_SECRET
      ) as TokenPayload;

      const user = await User.findById(decoded.id).select('-password');
      if (!user) {
        res.status(401).json({
          message: 'User not found',
          shouldReLogin: true,
        });
        return;
      }

      req.user = user;
      next();
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError && refreshToken) {
        res.status(401).json({
          message: 'Token expired',
          shouldRefresh: true,
        });
        return;
      }
      res.status(401).json({
        message: 'Invalid token',
        shouldReLogin: true,
      });
    }
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

const adminRefreshTokens = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const refreshToken = req.cookies?.admin_refreshToken;

    if (!refreshToken) {
      res.status(401).json({
        message: 'No refresh token',
        shouldReLogin: true,
      });
      return;
    }

    if (!process.env.REFRESH_TOKEN_SECRET) {
      throw new Error('REFRESH_TOKEN_SECRET is not defined');
    }

    try {
      const decoded = jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      ) as TokenPayload;

      const user = await User.findById(decoded.id).select('-password');
      if (!user) {
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
        res.status(401).json({
          message: 'User not found',
          shouldReLogin: true,
        });
        return;
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

      res.status(200).json({
        message: 'Tokens refreshed successfully',
      });
    } catch (error) {
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
      res.status(401).json({
        message: 'Invalid refresh token',
        shouldReLogin: true,
      });
    }
  } catch (err) {
    next(err);
  }
};

export { adminProtect, adminRefreshTokens };
