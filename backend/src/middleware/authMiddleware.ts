import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import User from '../models/userModel';
import generateTokens from '../utils/jwtUtils';
import { CustomRequest, TokenPayload } from '../interface/common.interface';

const protect = async (
  req: CustomRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const accessToken = req.cookies?.user_accessToken;
    const refreshToken = req.cookies?.user_refreshToken;

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

const refreshTokens = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const refreshToken = req.cookies?.user_refreshToken;

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
        res.status(401).json({
          message: 'User not found',
          shouldReLogin: true,
        });
        return;
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

      res.status(200).json({
        message: 'Tokens refreshed successfully',
      });
    } catch (error) {
      res.clearCookie('user_accessToken');
      res.clearCookie('user_refreshToken');
      res.status(401).json({
        message: 'Invalid refresh token',
        shouldReLogin: true,
      });
    }
  } catch (err) {
    next(err);
  }
};

export { protect, refreshTokens };
