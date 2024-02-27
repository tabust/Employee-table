const { prisma } = require('../prisma/prisma-client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

/**
 * @route POST /api/user/login
 * @desc Логин
 * @access Public
 */

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Please fill in the required fields' });
  }
  const user = await prisma.user.findFirst({
    where: {
      email,
    },
  });

  const isPasswordCorrect = user && (await bcrypt.compare(password, user.password));
  const secret = process.env.JWT_SECRET;

  if (user && isPasswordCorrect && secret) {
    res.status(200).json({
      id: user.id,
      email: user.email,
      name: user.name,
      token: jwt.sign({ id: user.id }, secret, { expiresIn: '30d' }),
    });
  } else {
    return res.status(400).json({ message: 'Invalid login or password' });
  }
};

/**
 * @route POST /api/user/register
 * @desc Регистрация
 * @access Public
 */

const register = async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ message: 'Please fill in the required fields' });
  }

  try {
    const registeredUser = await prisma.user.findFirst({
      where: {
        email,
      },
    });

    if (registeredUser) {
      return res.status(400).json({ message: 'This email is already used' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    const user = await prisma.user.create({
      data: {
        email,
        name,
        password: hashPassword,
      },
    });

    const secret = process.env.JWT_SECRET;

    if (user && secret) {
      res.status(201).json({
        id: user.id,
        email: user.email,
        name: user.name,
        token: jwt.sign({ id: user.id }, secret, { expiresIn: '30d' }),
      });
    } else {
      return res.status(400).json({ message: 'Failed to register' });
    }
  } catch (error) {
    return res.status(500).json({ message: 'Server error' });
  }
};

/**
 * @route GET /api/user/current
 * @desc Текущий пользователь
 * @access Private
 */

const current = async (req, res) => {
  return res.status(200).json(req.user);
};

module.exports = {
  login,
  register,
  current,
};
