const passport = require('passport');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { AppError } = require('./errorHandler');
const { sessionHelpers } = require('../config/redis');
const logger = require('../config/logger');

// Authenticate with JWT
const authenticateJWT = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (err, user, info) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      const message = info?.message || 'Authentication failed';
      return next(new AppError(message, 401, 'AUTHENTICATION_FAILED'));
    }

    req.user = user;
    next();
  })(req, res, next);
};

// Authenticate with local strategy (for login)
const authenticateLocal = (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      const message = info?.message || 'Invalid credentials';
      return next(new AppError(message, 401, 'INVALID_CREDENTIALS'));
    }

    req.user = user;
    next();
  })(req, res, next);
};

// Authenticate refresh token
const authenticateRefresh = (req, res, next) => {
  passport.authenticate('refresh', { session: false }, (err, user, info) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      const message = info?.message || 'Invalid refresh token';
      return next(new AppError(message, 401, 'INVALID_REFRESH_TOKEN'));
    }

    req.user = user;
    next();
  })(req, res, next);
};

// Optional authentication (doesn't fail if no token)
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }

  passport.authenticate('jwt', { session: false }, (err, user, info) => {
    if (err) {
      return next(err);
    }

    if (user) {
      req.user = user;
    }

    next();
  })(req, res, next);
};

// Role-based authorization
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'AUTHENTICATION_REQUIRED'));
    }

    if (!roles.includes(req.user.role)) {
      logger.warn('Unauthorized access attempt', {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles: roles,
        url: req.url,
        method: req.method,
        ip: req.ip
      });

      return next(new AppError('Insufficient permissions', 403, 'INSUFFICIENT_PERMISSIONS'));
    }

    next();
  };
};

// Check if user owns resource or has admin role
const authorizeOwnerOrAdmin = (resourceUserIdField = 'user_id') => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'AUTHENTICATION_REQUIRED'));
    }

    const resourceUserId = req.params[resourceUserIdField] || req.body[resourceUserIdField];
    
    if (req.user.role === 'admin' || req.user.id.toString() === resourceUserId?.toString()) {
      return next();
    }

    logger.warn('Unauthorized resource access attempt', {
      userId: req.user.id,
      userRole: req.user.role,
      resourceUserId,
      url: req.url,
      method: req.method,
      ip: req.ip
    });

    return next(new AppError('Access denied', 403, 'ACCESS_DENIED'));
  };
};

// Generate JWT token
const generateTokens = (user) => {
  const accessTokenPayload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    jti: uuidv4(),
    iat: Math.floor(Date.now() / 1000),
    iss: 'auth-system',
    aud: 'auth-system-users'
  };

  const refreshTokenPayload = {
    sub: user.id,
    jti: uuidv4(),
    iat: Math.floor(Date.now() / 1000),
    iss: 'auth-system',
    aud: 'auth-system-refresh'
  };

  const accessToken = jwt.sign(
    accessTokenPayload,
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
  );

  const refreshToken = jwt.sign(
    refreshTokenPayload,
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );

  return {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    accessTokenJti: accessTokenPayload.jti,
    refreshTokenJti: refreshTokenPayload.jti
  };
};

// Revoke tokens (add to blacklist)
const revokeTokens = async (accessTokenJti, refreshTokenJti) => {
  try {
    const promises = [];
    
    if (accessTokenJti) {
      promises.push(sessionHelpers.blacklistToken(accessTokenJti, 
        Math.floor(Date.now() / 1000) + 15 * 60)); // 15 minutes
    }
    
    if (refreshTokenJti) {
      promises.push(sessionHelpers.blacklistToken(refreshTokenJti, 
        Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60)); // 7 days
    }

    await Promise.all(promises);
    return true;
  } catch (error) {
    logger.error('Error revoking tokens:', error);
    throw error;
  }
};

// Require MFA verification
const requireMFA = (req, res, next) => {
  if (!req.user) {
    return next(new AppError('Authentication required', 401, 'AUTHENTICATION_REQUIRED'));
  }

  if (!req.user.mfa_enabled) {
    return next();
  }

  // Check if MFA was verified in this session
  if (!req.session?.mfaVerified || req.session.mfaUserId !== req.user.id) {
    return next(new AppError('MFA verification required', 403, 'MFA_REQUIRED'));
  }

  next();
};

// Check if account is verified
const requireVerification = (req, res, next) => {
  if (!req.user) {
    return next(new AppError('Authentication required', 401, 'AUTHENTICATION_REQUIRED'));
  }

  if (!req.user.is_verified) {
    return next(new AppError('Email verification required', 403, 'EMAIL_VERIFICATION_REQUIRED'));
  }

  next();
};

module.exports = {
  authenticateJWT,
  authenticateLocal,
  authenticateRefresh,
  optionalAuth,
  authorize,
  authorizeOwnerOrAdmin,
  generateTokens,
  revokeTokens,
  requireMFA,
  requireVerification
};