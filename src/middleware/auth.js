const jwt = require('jsonwebtoken');
const config = require('../config');

const authenticate = (req, res, next) => {
  const token = req.header('Authorization').replace('Bearer ', '');
  jwt.verify(token, config.jwtSecret, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

module.exports = authenticate;
