const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const { sessionHelpers } = require('../config/redis');
const { generateTokens, revokeTokens } = require('../middleware/auth');
const emailService = require('./emailService');
const logger = require('../config/logger');

class AuthService {
  // Register new user
  static async register(userData, req) {
    try {
      // Create user
      const user = await User.create(userData);

      // Send verification email
      await emailService.sendVerificationEmail(user.email, user.emailVerificationToken);

      // Log registration
      await User.logAuditEvent(
        null,
        user.id,
        'user_registered',
        'user',
        user.id,
        { role: user.role },
        req?.ip
      );

      logger.info('User registered successfully', {
        userId: user.id,
        email: user.email,
        role: user.role,
        ip: req?.ip
      });

      return {
        user: user.toJSON(),
        message: 'Registration successful. Please check your email for verification instructions.'
      };
    } catch (error) {
      logger.error('Registration failed:', error);
      throw error;
    }
  }

  // Login user
  static async login(user, req) {
    try {
      // Generate JWT tokens
      const tokens = generateTokens(user);

      // Store session in Redis
      await sessionHelpers.storeSession(user.id, {
        userId: user.id,
        email: user.email,
        role: user.role,
        loginTime: new Date(),
        ipAddress: req?.ip,
        userAgent: req?.get('User-Agent')
      });

      // Log successful login
      await User.logAuditEvent(
        null,
        user.id,
        'user_login',
        'user',
        user.id,
        { 
          mfaRequired: user.mfa_enabled,
          ipAddress: req?.ip,
          userAgent: req?.get('User-Agent')
        },
        req?.ip
      );

      logger.info('User logged in successfully', {
        userId: user.id,
        email: user.email,
        mfaEnabled: user.mfa_enabled,
        ip: req?.ip
      });

      return {
        user: user.toJSON(),
        tokens,
        mfaRequired: user.mfa_enabled && !req?.session?.mfaVerified
      };
    } catch (error) {
      logger.error('Login failed:', error);
      throw error;
    }
  }

  // Logout user
  static async logout(user, tokens, req) {
    try {
      // Revoke JWT tokens
      if (tokens?.accessTokenJti && tokens?.refreshTokenJti) {
        await revokeTokens(tokens.accessTokenJti, tokens.refreshTokenJti);
      }

      // Clear session from Redis
      await sessionHelpers.deleteSession(user.id);

      // Clear MFA verification from session
      if (req?.session) {
        req.session.mfaVerified = false;
        req.session.mfaUserId = null;
      }

      // Log logout
      await User.logAuditEvent(
        null,
        user.id,
        'user_logout',
        'user',
        user.id,
        null,
        req?.ip
      );

      logger.info('User logged out successfully', {
        userId: user.id,
        email: user.email,
        ip: req?.ip
      });

      return { message: 'Logged out successfully' };
    } catch (error) {
      logger.error('Logout failed:', error);
      throw error;
    }
  }

  // Refresh access token
  static async refreshToken(user, oldTokenPayload) {
    try {
      // Generate new tokens
      const tokens = generateTokens(user);

      // Blacklist old refresh token
      await sessionHelpers.blacklistToken(
        oldTokenPayload.jti,
        oldTokenPayload.exp || Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60
      );

      logger.info('Token refreshed successfully', {
        userId: user.id,
        email: user.email
      });

      return {
        user: user.toJSON(),
        tokens
      };
    } catch (error) {
      logger.error('Token refresh failed:', error);
      throw error;
    }
  }

  // Setup MFA for user
  static async setupMFA(userId) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      if (user.mfa_enabled) {
        throw new Error('MFA is already enabled for this user');
      }

      // Generate secret
      const secret = speakeasy.generateSecret({
        name: `${process.env.MFA_SERVICE_NAME || 'Auth System'} (${user.email})`,
        issuer: process.env.MFA_ISSUER || 'Auth System',
        length: 32
      });

      // Store temporary secret in Redis
      await sessionHelpers.storeMFASetupToken(userId, secret.base32, 600); // 10 minutes

      // Generate QR code
      const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

      logger.info('MFA setup initiated', {
        userId,
        email: user.email
      });

      return {
        secret: secret.base32,
        qrCode: qrCodeUrl,
        backupCodes: this.generateBackupCodes(),
        message: 'MFA setup initiated. Please scan the QR code with your authenticator app.'
      };
    } catch (error) {
      logger.error('MFA setup failed:', error);
      throw error;
    }
  }

  // Verify and enable MFA
  static async verifyAndEnableMFA(userId, token, secret) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Get secret from Redis if not provided
      if (!secret) {
        secret = await sessionHelpers.getMFASetupToken(userId);
        if (!secret) {
          throw new Error('MFA setup session expired. Please start setup again.');
        }
      }

      // Verify token
      const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 2
      });

      if (!verified) {
        throw new Error('Invalid MFA token');
      }

      // Enable MFA for user
      await user.setMFA(true, secret);

      // Clean up setup session
      await sessionHelpers.deleteMFASetupToken(userId);

      // Log MFA enablement
      await User.logAuditEvent(
        null,
        userId,
        'mfa_enabled',
        'user',
        userId
      );

      logger.info('MFA enabled successfully', {
        userId,
        email: user.email
      });

      return {
        message: 'MFA enabled successfully',
        backupCodes: this.generateBackupCodes()
      };
    } catch (error) {
      logger.error('MFA verification failed:', error);
      throw error;
    }
  }

  // Verify MFA token
  static async verifyMFA(userId, token, req) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      if (!user.mfa_enabled) {
        throw new Error('MFA is not enabled for this user');
      }

      const secret = user.getMFASecret();
      if (!secret) {
        throw new Error('MFA secret not found');
      }

      // Verify token
      const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 2
      });

      if (!verified) {
        // TODO: Check backup codes here
        throw new Error('Invalid MFA token');
      }

      // Mark MFA as verified in session
      if (req?.session) {
        req.session.mfaVerified = true;
        req.session.mfaUserId = userId;
        req.session.mfaVerifiedAt = new Date();
      }

      // Log MFA verification
      await User.logAuditEvent(
        null,
        userId,
        'mfa_verified',
        'user',
        userId,
        null,
        req?.ip
      );

      logger.info('MFA verified successfully', {
        userId,
        email: user.email,
        ip: req?.ip
      });

      return { message: 'MFA verified successfully' };
    } catch (error) {
      logger.error('MFA verification failed:', error);
      throw error;
    }
  }

  // Disable MFA
  static async disableMFA(userId, token) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      if (!user.mfa_enabled) {
        throw new Error('MFA is not enabled for this user');
      }

      const secret = user.getMFASecret();
      if (!secret) {
        throw new Error('MFA secret not found');
      }

      // Verify token before disabling
      const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 2
      });

      if (!verified) {
        throw new Error('Invalid MFA token');
      }

      // Disable MFA
      await user.setMFA(false);

      // Log MFA disablement
      await User.logAuditEvent(
        null,
        userId,
        'mfa_disabled',
        'user',
        userId
      );

      logger.info('MFA disabled successfully', {
        userId,
        email: user.email
      });

      return { message: 'MFA disabled successfully' };
    } catch (error) {
      logger.error('MFA disable failed:', error);
      throw error;
    }
  }

  // Request password reset
  static async requestPasswordReset(email, req) {
    try {
      const result = await User.createPasswordResetToken(email);

      // Send password reset email
      await emailService.sendPasswordResetEmail(email, result.token);

      // Log password reset request
      await User.logAuditEvent(
        null,
        result.userId,
        'password_reset_requested',
        'user',
        result.userId,
        null,
        req?.ip
      );

      logger.info('Password reset requested', {
        userId: result.userId,
        email,
        ip: req?.ip
      });

      return {
        message: 'Password reset instructions have been sent to your email'
      };
    } catch (error) {
      // Don't reveal if email doesn't exist
      if (error.message === 'User not found') {
        logger.warn('Password reset requested for non-existent email', {
          email,
          ip: req?.ip
        });
        return {
          message: 'Password reset instructions have been sent to your email'
        };
      }

      logger.error('Password reset request failed:', error);
      throw error;
    }
  }

  // Reset password
  static async resetPassword(token, newPassword, req) {
    try {
      await User.resetPassword(token, newPassword);

      logger.info('Password reset successfully', {
        ip: req?.ip
      });

      return { message: 'Password reset successfully' };
    } catch (error) {
      logger.error('Password reset failed:', error);
      throw error;
    }
  }

  // Change password
  static async changePassword(userId, currentPassword, newPassword, req) {
    try {
      const user = await User.findByEmail(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Verify current password
      const isValid = await user.verifyPassword(currentPassword);
      if (!isValid) {
        throw new Error('Current password is incorrect');
      }

      // Change password
      await user.changePassword(newPassword);

      // Log password change
      await User.logAuditEvent(
        null,
        userId,
        'password_changed',
        'user',
        userId,
        null,
        req?.ip
      );

      logger.info('Password changed successfully', {
        userId,
        email: user.email,
        ip: req?.ip
      });

      return { message: 'Password changed successfully' };
    } catch (error) {
      logger.error('Password change failed:', error);
      throw error;
    }
  }

  // Verify email
  static async verifyEmail(token, req) {
    try {
      await User.verifyEmail(token);

      logger.info('Email verified successfully', {
        ip: req?.ip
      });

      return { message: 'Email verified successfully' };
    } catch (error) {
      logger.error('Email verification failed:', error);
      throw error;
    }
  }

  // Generate backup codes for MFA
  static generateBackupCodes() {
    const codes = [];
    for (let i = 0; i < 10; i++) {
      codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }
    return codes;
  }

  // Validate session
  static async validateSession(userId) {
    try {
      const session = await sessionHelpers.getSession(userId);
      if (!session) {
        return null;
      }

      const user = await User.findById(userId);
      if (!user || !user.is_active || !user.is_verified) {
        await sessionHelpers.deleteSession(userId);
        return null;
      }

      return {
        user: user.toJSON(),
        session
      };
    } catch (error) {
      logger.error('Session validation failed:', error);
      return null;
    }
  }

  // Revoke all sessions for user
  static async revokeAllSessions(userId) {
    try {
      // Clear Redis session
      await sessionHelpers.deleteSession(userId);

      // Clear database sessions
      await query(`
        UPDATE user_sessions SET is_active = false
        WHERE user_id = $1 AND is_active = true
      `, [userId]);

      // Log session revocation
      await User.logAuditEvent(
        null,
        userId,
        'all_sessions_revoked',
        'user',
        userId
      );

      logger.info('All sessions revoked for user', { userId });

      return { message: 'All sessions revoked successfully' };
    } catch (error) {
      logger.error('Session revocation failed:', error);
      throw error;
    }
  }
}

module.exports = AuthService;