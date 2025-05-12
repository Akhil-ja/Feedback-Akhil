import { Router } from 'express';
import adminRoutes from './adminRoute';
import userRoutes from './userRoute';
import sharedRoutes from './sharedRoute';

const router = Router();

router.use('/admin', adminRoutes);
router.use('/employee', userRoutes);
router.use('/', sharedRoutes);

export default router;
