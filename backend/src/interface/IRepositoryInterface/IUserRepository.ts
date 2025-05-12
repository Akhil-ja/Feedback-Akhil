import { IUser } from '../common.interface';

export interface IUserRepository {
  findById(userId: string): Promise<IUser | null>;
  getAllUsers(): Promise<IUser[]>;
  findByEmail(email: string): Promise<IUser | null>;
  createUser(userData: Partial<IUser>): Promise<IUser>;
  updateUser(userId: string, updates: Partial<IUser>): Promise<IUser>;
  saveUser(userId: string, userData: IUser): Promise<IUser>;
}
