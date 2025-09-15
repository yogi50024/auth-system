const AuthService = require('../services/authService');
const { catchAsync } = require('../middleware/errorHandler');
const { AppError } = require('../middleware/errorHandler');
const logger = require('../config/logger');

class AuthController {
  // Register new user
  static register = catchAsync(async (req, res) => {
    const result = await AuthService.register(req.body, req);
    
    res.status(201).json({
      status: 'success',
      message: result.message,
      data: {
        user: result.user
      }
    });
  });

  // Login user
  static login = catchAsync(async (req, res) => {
    const result = await AuthService.login(req.user, req);
    
    // Set secure cookies for tokens if in production
    if (process.env.NODE_ENV === 'production') {
      res.cookie('access_token', result.tokens.accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      res.cookie('refresh_token', result.tokens.refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Login successful',
      data: {
        user: result.user,
        tokens: result.tokens,
        mfaRequired: result.mfaRequired
      }
    });
  });

  // Logout user
  static logout = catchAsync(async (req, res) => {
    const tokens = {
      accessTokenJti: req.user?.tokenPayload?.jti,
      refreshTokenJti: req.body?.refresh_token_jti
    };

    await AuthService.logout(req.user, tokens, req);

    // Clear cookies
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    res.status(200).json({
      status: 'success',
      message: 'Logged out successfully'
    });
  });

  // Refresh access token
  static refreshToken = catchAsync(async (req, res) => {
    const result = await AuthService.refreshToken(req.user, req.user.tokenPayload);

    res.status(200).json({
      status: 'success',
      message: 'Token refreshed successfully',
      data: {
        user: result.user,
        tokens: result.tokens
      }
    });
  });

  // Get current user profile
  static getProfile = catchAsync(async (req, res) => {
    res.status(200).json({
      status: 'success',
      data: {
        user: req.user
      }
    });
  });

  // Setup MFA
  static setupMFA = catchAsync(async (req, res) => {
    const result = await AuthService.setupMFA(req.user.id);

    res.status(200).json({
      status: 'success',
      message: result.message,
      data: {
        secret: result.secret,
        qrCode: result.qrCode,
        backupCodes: result.backupCodes
      }
    });
  });

  // Verify and enable MFA
  static verifyMFA = catchAsync(async (req, res) => {
    const { token, secret } = req.body;
    const result = await AuthService.verifyAndEnableMFA(req.user.id, token, secret);

    res.status(200).json({
      status: 'success',
      message: result.message,
      data: {
        backupCodes: result.backupCodes
      }
    });
  });

  // Verify MFA for login
  static verifyMFALogin = catchAsync(async (req, res) => {
    const { token } = req.body;
    const result = await AuthService.verifyMFA(req.user.id, token, req);

    res.status(200).json({
      status: 'success',
      message: result.message
    });
  });

  // Disable MFA
  static disableMFA = catchAsync(async (req, res) => {
    const { token } = req.body;
    const result = await AuthService.disableMFA(req.user.id, token);

    res.status(200).json({
      status: 'success',
      message: result.message
    });
  });

  // Request password reset
  static requestPasswordReset = catchAsync(async (req, res) => {
    const { email } = req.body;
    const result = await AuthService.requestPasswordReset(email, req);

    res.status(200).json({
      status: 'success',
      message: result.message
    });
  });

  // Reset password
  static resetPassword = catchAsync(async (req, res) => {
    const { token, password } = req.body;
    const result = await AuthService.resetPassword(token, password, req);

    res.status(200).json({
      status: 'success',
      message: result.message
    });
  });

  // Change password
  static changePassword = catchAsync(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const result = await AuthService.changePassword(
      req.user.id, 
      currentPassword, 
      newPassword, 
      req
    );

    res.status(200).json({
      status: 'success',
      message: result.message
    });
  });

  // Verify email
  static verifyEmail = catchAsync(async (req, res) => {
    const { token } = req.body;
    const result = await AuthService.verifyEmail(token, req);

    res.status(200).json({
      status: 'success',
      message: result.message
    });
  });

  // Resend verification email
  static resendVerificationEmail = catchAsync(async (req, res) => {
    const { email } = req.body;
    
    // This would need to be implemented in AuthService
    throw new AppError('Feature not yet implemented', 501);
  });

  // Validate session
  static validateSession = catchAsync(async (req, res) => {
    const result = await AuthService.validateSession(req.user.id);
    
    if (!result) {
      throw new AppError('Invalid session', 401);
    }

    res.status(200).json({
      status: 'success',
      data: {
        user: result.user,
        session: result.session
      }
    });
  });

  // Revoke all sessions
  static revokeAllSessions = catchAsync(async (req, res) => {
    const result = await AuthService.revokeAllSessions(req.user.id);

    res.status(200).json({
      status: 'success',
      message: result.message
    });
  });

  // Check authentication status
  static checkAuth = catchAsync(async (req, res) => {
    res.status(200).json({
      status: 'success',
      data: {
        authenticated: true,
        user: req.user,
        mfaRequired: req.user.mfa_enabled && !req.session?.mfaVerified
      }
    });
  });
}

module.exports = AuthController;