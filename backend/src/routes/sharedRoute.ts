import { Router } from 'express';
import { UserRepository } from '../repositories/userRepository';
import { SharedController } from '../controller/sharedController';
import { SharedService } from '../services/sharedServices';
import { protect } from '../middleware/authMiddleware';

const router = Router();

const userRepository = new UserRepository();

const sharedService = new SharedService(userRepository);
const sharedController = new SharedController(sharedService);

router.post('/signin', (req, res, next) =>
  sharedController.signIn(req, res, next)
);

router.post('/forgot-password', (req, res, next) =>
  sharedController.forgotPassword(req, res, next)
);

router.post('/verify-otp', (req, res, next) =>
  sharedController.verifyForgotOTP(req, res, next)
);

router.post('/change-password', protect, (req, res, next) =>
  sharedController.changePassword(req, res, next)
);

router.post('/logout', (req, res, next) =>
  sharedController.logout(req, res, next)
);

export default router;
