import { Router } from 'express';
import { AdminController } from '../controller/adminController';
import { UserRepository } from '../repositories/userRepository';
import { AdminService } from '../services/adminServices';

const router = Router();

const userRepository = new UserRepository();

const adminService = new AdminService(userRepository);
const adminController = new AdminController(adminService);

router.post('/signin', (req, res, next) =>
  adminController.signIn(req, res, next)
);

router.post('/create-user', (req, res, next) =>
  adminController.createUser(req, res, next)
);
router.post('/logout', (req, res, next) =>
  adminController.logout(req, res, next)
);

export default router;
