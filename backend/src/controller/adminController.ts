import { IAdminService } from '../interface/IServiceInterface/IAdminServices';
import { AppError } from '../utils/appError';
import { Request, Response, NextFunction } from 'express';

export class AdminController {
  constructor(private readonly AdminService: IAdminService) {}

  signIn = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const { email, password } = req.body;

    try {
      const { user, tokens } = await this.AdminService.adminSignIn(
        email,
        password,
        res,
        req
      );
      res.status(200).json({
        message: 'Sign in successful',
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          first_name: user.first_name,
          last_name: user.last_name,
        },
        tokens,
      });
    } catch (error) {
      console.error('Error during Sign-in:', error);
      next(
        error instanceof AppError
          ? error
          : new AppError('Failed to signin', 400)
      );
    }
  };

  createUser = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const { email, password, firstName, lastName, role } = req.body;

    try {
      const result = await this.AdminService.createUser({
        email,
        password,
        role,
        firstName,
        lastName,
      });

      res.status(201).json({
        message: 'User created successfully',
        user: result,
      });
    } catch (error) {
      console.error('Error creating user:', error);
      next(
        error instanceof AppError
          ? error
          : new AppError('Failed to create user', 400)
      );
    }
  };

  logout = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      await this.AdminService.Adminlogout(res);
      res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
      console.error('Error during logout:', error);
      next(
        error instanceof AppError ? error : new AppError('Logout failed', 500)
      );
    }
  };
}
