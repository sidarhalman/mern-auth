import express from 'express';
import userAuth from '../middleware/userAuth.js';
import { getUserData ,getAllUsers } from '../controllers/userController.js';
const userRouter = express.Router();

userRouter.get('/data',  userAuth, getUserData )
userRouter.get('/all-users', getAllUsers)

export default userRouter;
