const { getAll, create, getOne, remove, update, verifyCode, login, me, resetPassword, newPassword } = require('../controllers/user.controllers');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT');

const userRouter = express.Router();

userRouter.route('/')
    .get(verifyJWT, getAll)
    .post(create);

userRouter.route('/login')
    .post(login);

userRouter.route('/me')
    .get(verifyJWT, me);

userRouter.route('/reset_password')
    .post(resetPassword);
userRouter.route('/reset_password/:code')
    .post(newPassword);

userRouter.route('/verify/:code')
    .get(verifyCode);

userRouter.route('/:id')
    .get(verifyJWT, getOne)
    .delete(verifyJWT, remove)
    .put(verifyJWT, update);

module.exports = userRouter;