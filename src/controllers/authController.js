const jwt = require('jsonwebtoken');
const config = require('../config');
const { hashPassword } = require('../utils/crypto');

const login = (req, res) => {
  const { username, password } = req.body;
  // Authentication logic here
  const token = jwt.sign({ username }, config.jwtSecret);
  res.json({ token });
};

module.exports = { login };
