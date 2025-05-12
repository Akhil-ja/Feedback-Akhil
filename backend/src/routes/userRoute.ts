import { Router } from 'express';
import { UserRepository } from '../repositories/userRepository';
import { UserService } from '../services/userServices';
import { UserController } from '../controller/userController';
import { protect } from '../middleware/authMiddleware';

const router = Router();

const userRepository = new UserRepository();

const userService = new UserService(userRepository);
const userController = new UserController(userService);

router.post('/profile', (req, res, next) =>
  userController.fetchUserProfile(req, res, next)
);

export default router;
