const rateLimit = require('express-rate-limit');
const { sessionHelpers } = require('../config/redis');
const { AppError } = require('./errorHandler');
const logger = require('../config/logger');

// Create rate limiter with Redis store
const createRateLimiter = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes
    max = 100,
    message = 'Too many requests from this IP, please try again later.',
    keyGenerator = (req) => req.ip,
    skipSuccessfulRequests = false,
    skipFailedRequests = false
  } = options;

  return rateLimit({
    windowMs,
    max,
    message: {
      error: message,
      retryAfter: Math.ceil(windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator,
    skipSuccessfulRequests,
    skipFailedRequests,
    handler: (req, res, next) => {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        url: req.url,
        method: req.method,
        userAgent: req.get('User-Agent'),
        userId: req.user?.id
      });

      return next(new AppError(message, 429, 'RATE_LIMIT_EXCEEDED'));
    }
  });
};

// Login rate limiter (stricter)
const loginRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX) || 5,
  message: 'Too many login attempts from this IP, please try again after 15 minutes.',
  keyGenerator: (req) => `login:${req.ip}`,
  skipSuccessfulRequests: true
});

// Registration rate limiter
const registerRateLimit = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: parseInt(process.env.REGISTER_RATE_LIMIT_MAX) || 3,
  message: 'Too many registration attempts from this IP, please try again after 1 hour.',
  keyGenerator: (req) => `register:${req.ip}`,
  skipSuccessfulRequests: true
});

// Password reset rate limiter
const passwordResetRateLimit = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: 'Too many password reset attempts, please try again after 1 hour.',
  keyGenerator: (req) => `password-reset:${req.ip}`,
  skipSuccessfulRequests: true
});

// MFA verification rate limiter
const mfaRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: 'Too many MFA verification attempts, please try again after 15 minutes.',
  keyGenerator: (req) => `mfa:${req.ip}:${req.user?.id || 'anonymous'}`,
  skipSuccessfulRequests: true
});

// Email verification rate limiter
const emailVerificationRateLimit = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: 'Too many email verification requests, please try again after 1 hour.',
  keyGenerator: (req) => `email-verify:${req.ip}`,
  skipSuccessfulRequests: true
});

// GDPR export rate limiter (per user)
const gdprExportRateLimit = createRateLimiter({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: parseInt(process.env.GDPR_EXPORT_LIMIT_PER_DAY) || 3,
  message: 'Too many data export requests, please try again tomorrow.',
  keyGenerator: (req) => `gdpr-export:${req.user?.id || req.ip}`,
  skipSuccessfulRequests: true
});

// File upload rate limiter
const fileUploadRateLimit = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: 'Too many file upload attempts, please try again after 1 hour.',
  keyGenerator: (req) => `upload:${req.user?.id || req.ip}`,
  skipSuccessfulRequests: true
});

// Custom rate limiter using Redis directly
const customRateLimit = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000,
    max = 100,
    keyGenerator = (req) => req.ip,
    message = 'Too many requests, please try again later.'
  } = options;

  return async (req, res, next) => {
    try {
      const key = `rate-limit:${keyGenerator(req)}`;
      const windowStart = Math.floor(Date.now() / windowMs) * windowMs;
      const redisKey = `${key}:${windowStart}`;

      const current = await sessionHelpers.incrementRateLimit(redisKey, Math.ceil(windowMs / 1000));

      // Set headers
      res.set({
        'X-RateLimit-Limit': max,
        'X-RateLimit-Remaining': Math.max(0, max - current),
        'X-RateLimit-Reset': Math.ceil((windowStart + windowMs) / 1000)
      });

      if (current > max) {
        logger.warn('Custom rate limit exceeded', {
          key: redisKey,
          current,
          max,
          ip: req.ip,
          url: req.url,
          method: req.method,
          userId: req.user?.id
        });

        return next(new AppError(message, 429, 'RATE_LIMIT_EXCEEDED'));
      }

      next();
    } catch (error) {
      logger.error('Rate limit middleware error:', error);
      // Fail open - allow request if Redis is down
      next();
    }
  };
};

// Per-user rate limiter
const perUserRateLimit = (options = {}) => {
  return customRateLimit({
    ...options,
    keyGenerator: (req) => req.user?.id || req.ip
  });
};

// Sliding window rate limiter
const slidingWindowRateLimit = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000,
    max = 100,
    keyGenerator = (req) => req.ip,
    message = 'Too many requests, please try again later.'
  } = options;

  return async (req, res, next) => {
    try {
      const key = `sliding:${keyGenerator(req)}`;
      const now = Date.now();
      const windowStart = now - windowMs;

      // This would require more complex Redis operations for true sliding window
      // For now, using fixed window approach
      const windowKey = `${key}:${Math.floor(now / windowMs)}`;
      const current = await sessionHelpers.incrementRateLimit(windowKey, Math.ceil(windowMs / 1000));

      if (current > max) {
        logger.warn('Sliding window rate limit exceeded', {
          key: windowKey,
          current,
          max,
          ip: req.ip,
          url: req.url,
          method: req.method,
          userId: req.user?.id
        });

        return next(new AppError(message, 429, 'RATE_LIMIT_EXCEEDED'));
      }

      next();
    } catch (error) {
      logger.error('Sliding window rate limit error:', error);
      // Fail open - allow request if Redis is down
      next();
    }
  };
};

module.exports = {
  createRateLimiter,
  loginRateLimit,
  registerRateLimit,
  passwordResetRateLimit,
  mfaRateLimit,
  emailVerificationRateLimit,
  gdprExportRateLimit,
  fileUploadRateLimit,
  customRateLimit,
  perUserRateLimit,
  slidingWindowRateLimit
};