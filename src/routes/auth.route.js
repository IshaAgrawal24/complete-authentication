import { Router } from "express";
import * as authController from '../controllers/auth.controller.js';

const authRouter = Router();

// Registration API 
authRouter.post('/register', authController.register);

authRouter.get('/get-me', authController.getMe)

authRouter.get('/refresh-token', authController.getRefreshToken)

export default authRouter;