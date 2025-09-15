const express = require('express');
const AuthController = require('../controllers/authController');
const {
  authenticateLocal,
  authenticateJWT,
  authenticateRefresh,
  requireMFA
} = require('../middleware/auth');
const {
  loginRateLimit,
  registerRateLimit,
  passwordResetRateLimit,
  mfaRateLimit,
  emailVerificationRateLimit
} = require('../middleware/rateLimiter');
const {
  validateUserRegistration,
  validateUserLogin,
  validatePasswordResetRequest,
  validatePasswordReset,
  validateChangePassword,
  validateMFASetup,
  validateMFAVerification,
  validateEmailVerification,
  validateRefreshToken
} = require('../middleware/validation');

const router = express.Router();

// Public routes
router.post('/register', 
  registerRateLimit,
  validateUserRegistration,
  AuthController.register
);

router.post('/login',
  loginRateLimit,
  validateUserLogin,
  authenticateLocal,
  AuthController.login
);

router.post('/refresh-token',
  validateRefreshToken,
  authenticateRefresh,
  AuthController.refreshToken
);

router.post('/password-reset/request',
  passwordResetRateLimit,
  validatePasswordResetRequest,
  AuthController.requestPasswordReset
);

router.post('/password-reset/confirm',
  passwordResetRateLimit,
  validatePasswordReset,
  AuthController.resetPassword
);

router.post('/verify-email',
  emailVerificationRateLimit,
  validateEmailVerification,
  AuthController.verifyEmail
);

// Protected routes (require authentication)
router.use(authenticateJWT);

router.get('/profile', AuthController.getProfile);

router.post('/logout', AuthController.logout);

router.post('/change-password',
  validateChangePassword,
  AuthController.changePassword
);

router.get('/check', AuthController.checkAuth);

router.get('/validate-session', AuthController.validateSession);

router.post('/revoke-sessions', AuthController.revokeAllSessions);

// MFA routes
router.post('/mfa/setup',
  mfaRateLimit,
  AuthController.setupMFA
);

router.post('/mfa/verify',
  mfaRateLimit,
  validateMFAVerification,
  AuthController.verifyMFA
);

router.post('/mfa/verify-login',
  mfaRateLimit,
  validateMFAVerification,
  AuthController.verifyMFALogin
);

router.post('/mfa/disable',
  mfaRateLimit,
  validateMFAVerification,
  AuthController.disableMFA
);

module.exports = router;