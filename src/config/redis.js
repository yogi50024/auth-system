const redis = require('redis');
const logger = require('./logger');

// Redis client configuration
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT) || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  db: parseInt(process.env.REDIS_DB) || 0,
  retryDelayOnFailover: 100,
  enableReadyCheck: true,
  maxRetriesPerRequest: 3,
  connectTimeout: 5000,
  lazyConnect: true
});

// Redis event handlers
redisClient.on('connect', () => {
  logger.info('Redis client connecting...');
});

redisClient.on('ready', () => {
  logger.info('Redis client connected and ready');
});

redisClient.on('error', (error) => {
  logger.error('Redis client error:', error);
});

redisClient.on('end', () => {
  logger.info('Redis client disconnected');
});

redisClient.on('reconnecting', () => {
  logger.info('Redis client reconnecting...');
});

// Helper functions for session management
const sessionHelpers = {
  // Store user session
  async storeSession(userId, sessionData, ttl = 1800) {
    try {
      const key = `session:${userId}`;
      await redisClient.setEx(key, ttl, JSON.stringify(sessionData));
      return true;
    } catch (error) {
      logger.error('Error storing session:', error);
      throw error;
    }
  },

  // Get user session
  async getSession(userId) {
    try {
      const key = `session:${userId}`;
      const sessionData = await redisClient.get(key);
      return sessionData ? JSON.parse(sessionData) : null;
    } catch (error) {
      logger.error('Error getting session:', error);
      throw error;
    }
  },

  // Delete user session
  async deleteSession(userId) {
    try {
      const key = `session:${userId}`;
      await redisClient.del(key);
      return true;
    } catch (error) {
      logger.error('Error deleting session:', error);
      throw error;
    }
  },

  // Store JWT token blacklist
  async blacklistToken(jti, exp) {
    try {
      const key = `blacklist:${jti}`;
      const ttl = Math.max(1, exp - Math.floor(Date.now() / 1000));
      await redisClient.setEx(key, ttl, '1');
      return true;
    } catch (error) {
      logger.error('Error blacklisting token:', error);
      throw error;
    }
  },

  // Check if token is blacklisted
  async isTokenBlacklisted(jti) {
    try {
      const key = `blacklist:${jti}`;
      const exists = await redisClient.exists(key);
      return exists === 1;
    } catch (error) {
      logger.error('Error checking token blacklist:', error);
      throw error;
    }
  },

  // Store rate limit data
  async incrementRateLimit(key, windowSize) {
    try {
      const multi = redisClient.multi();
      multi.incr(key);
      multi.expire(key, windowSize);
      const results = await multi.exec();
      return results[0][1]; // Return the incremented count
    } catch (error) {
      logger.error('Error incrementing rate limit:', error);
      throw error;
    }
  },

  // Store password reset token
  async storePasswordResetToken(token, userId, ttl = 3600) {
    try {
      const key = `password-reset:${token}`;
      await redisClient.setEx(key, ttl, userId.toString());
      return true;
    } catch (error) {
      logger.error('Error storing password reset token:', error);
      throw error;
    }
  },

  // Get password reset token
  async getPasswordResetToken(token) {
    try {
      const key = `password-reset:${token}`;
      const userId = await redisClient.get(key);
      if (userId) {
        await redisClient.del(key); // Use token only once
        return parseInt(userId);
      }
      return null;
    } catch (error) {
      logger.error('Error getting password reset token:', error);
      throw error;
    }
  },

  // Store MFA setup token
  async storeMFASetupToken(userId, secret, ttl = 600) {
    try {
      const key = `mfa-setup:${userId}`;
      await redisClient.setEx(key, ttl, secret);
      return true;
    } catch (error) {
      logger.error('Error storing MFA setup token:', error);
      throw error;
    }
  },

  // Get MFA setup token
  async getMFASetupToken(userId) {
    try {
      const key = `mfa-setup:${userId}`;
      const secret = await redisClient.get(key);
      return secret;
    } catch (error) {
      logger.error('Error getting MFA setup token:', error);
      throw error;
    }
  },

  // Delete MFA setup token
  async deleteMFASetupToken(userId) {
    try {
      const key = `mfa-setup:${userId}`;
      await redisClient.del(key);
      return true;
    } catch (error) {
      logger.error('Error deleting MFA setup token:', error);
      throw error;
    }
  }
};

module.exports = {
  redisClient,
  sessionHelpers
};