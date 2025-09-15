require('dotenv').config();

module.exports = {
  jwtSecret: process.env.JWT_SECRET,
  dbUri: process.env.DB_URI,
  redisUrl: process.env.REDIS_URL,
  port: process.env.PORT,
};
