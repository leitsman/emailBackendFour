const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');

// { attributes: { exclude: ['createdAt', 'updatedAt'] } }
// { attributes: ['properties','properties2'] }
const frontBaseUrl = ``
const getAll = catchError(async (req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async (req, res) => {
    // const { email, password, firstName, lastName, country, image } = req.body;
    const encrypted = await bcrypt.hash(req.body.password, 10)
    const result = await User.create({ ...req.body, password: encrypted });
    const code = require('crypto').randomBytes(32).toString('hex')
    const link = `${frontBaseUrl}/verify_email/${code}`
    await sendEmail({
        to: req.body.email,
        subject: "email verification",
        html: `<h1>Hello ${req.body.firstName} ${req.body.lastName}</h1>
        <p>Verify your account clicking this <a href="${link}">link</a></p>
        <strong>Thank you!</strong>`
    });
    await EmailCode.create({ code, userId: result.id })
    return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if (!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async (req, res) => {
    const { id } = req.params;
    await User.destroy({ where: { id } });
    return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
    const { id } = req.params;
    const result = await User.update(
        req.body,
        { where: { id }, returning: true }
    );
    if (result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyCode = catchError(async (req, res) => {
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({ where: { code } })
    if (!emailCode) return res.status(401).json({ Message: 'Code Invalid' });
    await User.update({ isVerified: true }, { where: { id: emailCode.userId } })
    await emailCode.destroy()
    return res.json(emailCode);
});

const login = catchError(async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } })
    if (!user) return res.status(401).json({ Message: 'Email Not Found' });
    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) return res.status(401).json({ Message: 'Invalid Password' });
    if (!user.isVerified) return res.status(401).json({ Message: 'User Not Verified' });
    const token = jwt.sign(
        { user },
        process.env.TOKEN_SECRET,
        { expiresIn: '1d' }
    );
    return res.json({ user, token })
});

const me = catchError(async (req, res) => {
    return res.json(req.user)
});

const resetPassword = catchError(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ where: { email } })
    if (!user) return res.status(401).json({ Message: 'Email Not Found!' });
    const code = require('crypto').randomBytes(32).toString('hex')
    const link = `${frontBaseUrl}/reset_password/${code}`
    await sendEmail({
        to: email,
        subject: "Reset Password",
        html: `<h1>Hello!!!</h1>
        <p>Reset your password clicking this <a href="${link}">link</a></p>
        <strong>Thank you!</strong>`
    });
    await EmailCode.create({ code, userId: user.id })
    return res.json(user)
});

const newPassword = catchError(async (req, res) => {
    const { password } = req.body;
    const { code } = req.params;
    const user = await EmailCode.findOne({ where: { code } })
    if (!user) return res.status(401).json({ Message: 'Email Not Found!' });
    const passwordHash = await bcrypt.hash(password, 10)
    await User.update({ password: passwordHash }, { where: { id: user.userId } });
    await user.destroy();
    return res.json(user)
});

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyCode,
    login,
    me,
    resetPassword,
    newPassword,
}