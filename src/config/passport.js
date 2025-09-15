const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const argon2 = require('argon2');
const { query } = require('./database');
const { sessionHelpers } = require('./redis');
const logger = require('./logger');

// Local Strategy for username/password authentication
passport.use('local', new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
  passReqToCallback: true
}, async (req, email, password, done) => {
  try {
    // Find user by email
    const result = await query(
      'SELECT id, email, password_hash, is_active, is_verified, failed_login_attempts, locked_until, mfa_enabled FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (result.rows.length === 0) {
      logger.warn('Login attempt with non-existent email', { email, ip: req.ip });
      return done(null, false, { message: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Check if account is active
    if (!user.is_active) {
      logger.warn('Login attempt with inactive account', { userId: user.id, email });
      return done(null, false, { message: 'Account is deactivated' });
    }

    // Check if account is verified
    if (!user.is_verified) {
      logger.warn('Login attempt with unverified account', { userId: user.id, email });
      return done(null, false, { message: 'Please verify your email before logging in' });
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      logger.warn('Login attempt with locked account', { userId: user.id, email });
      return done(null, false, { message: 'Account is temporarily locked. Please try again later.' });
    }

    // Verify password
    const passwordValid = await argon2.verify(user.password_hash, password);
    
    if (!passwordValid) {
      // Increment failed login attempts
      const newFailedAttempts = (user.failed_login_attempts || 0) + 1;
      let lockUntil = null;
      
      // Lock account after 5 failed attempts for 15 minutes
      if (newFailedAttempts >= 5) {
        lockUntil = new Date(Date.now() + 15 * 60 * 1000);
      }

      await query(
        'UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3',
        [newFailedAttempts, lockUntil, user.id]
      );

      logger.warn('Failed login attempt', { 
        userId: user.id, 
        email, 
        attempts: newFailedAttempts,
        ip: req.ip 
      });

      return done(null, false, { message: 'Invalid credentials' });
    }

    // Reset failed login attempts on successful password verification
    if (user.failed_login_attempts > 0) {
      await query(
        'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1',
        [user.id]
      );
    }

    // Update last login
    await query(
      'UPDATE users SET last_login = NOW() WHERE id = $1',
      [user.id]
    );

    logger.info('Successful login', { userId: user.id, email, ip: req.ip });

    // Return user without password hash
    const { password_hash, ...userWithoutPassword } = user;
    return done(null, userWithoutPassword);

  } catch (error) {
    logger.error('Local strategy error:', error);
    return done(error);
  }
}));

// JWT Strategy for token authentication
passport.use('jwt', new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET,
  issuer: 'auth-system',
  audience: 'auth-system-users',
  passReqToCallback: true
}, async (req, payload, done) => {
  try {
    // Check if token is blacklisted
    const isBlacklisted = await sessionHelpers.isTokenBlacklisted(payload.jti);
    if (isBlacklisted) {
      logger.warn('Blacklisted token used', { userId: payload.sub, jti: payload.jti });
      return done(null, false, { message: 'Token has been revoked' });
    }

    // Find user by ID
    const result = await query(
      `SELECT id, email, first_name, last_name, role, is_active, is_verified, 
       mfa_enabled, last_login, created_at FROM users WHERE id = $1`,
      [payload.sub]
    );

    if (result.rows.length === 0) {
      logger.warn('JWT token for non-existent user', { userId: payload.sub });
      return done(null, false, { message: 'User not found' });
    }

    const user = result.rows[0];

    // Check if account is still active
    if (!user.is_active) {
      logger.warn('JWT token for inactive user', { userId: user.id });
      return done(null, false, { message: 'Account is deactivated' });
    }

    // Check if account is verified
    if (!user.is_verified) {
      logger.warn('JWT token for unverified user', { userId: user.id });
      return done(null, false, { message: 'Account not verified' });
    }

    // Add token info to user object
    user.tokenPayload = payload;

    return done(null, user);

  } catch (error) {
    logger.error('JWT strategy error:', error);
    return done(error);
  }
}));

// Refresh Token Strategy
passport.use('refresh', new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromBodyField('refresh_token'),
  secretOrKey: process.env.JWT_REFRESH_SECRET,
  issuer: 'auth-system',
  audience: 'auth-system-refresh',
  passReqToCallback: true
}, async (req, payload, done) => {
  try {
    // Check if token is blacklisted
    const isBlacklisted = await sessionHelpers.isTokenBlacklisted(payload.jti);
    if (isBlacklisted) {
      logger.warn('Blacklisted refresh token used', { userId: payload.sub, jti: payload.jti });
      return done(null, false, { message: 'Refresh token has been revoked' });
    }

    // Find user by ID
    const result = await query(
      'SELECT id, email, is_active, is_verified FROM users WHERE id = $1',
      [payload.sub]
    );

    if (result.rows.length === 0) {
      logger.warn('Refresh token for non-existent user', { userId: payload.sub });
      return done(null, false, { message: 'User not found' });
    }

    const user = result.rows[0];

    // Check if account is still active
    if (!user.is_active) {
      logger.warn('Refresh token for inactive user', { userId: user.id });
      return done(null, false, { message: 'Account is deactivated' });
    }

    // Add token info to user object
    user.tokenPayload = payload;

    return done(null, user);

  } catch (error) {
    logger.error('Refresh token strategy error:', error);
    return done(error);
  }
}));

// Serialize user for session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
    const result = await query(
      `SELECT id, email, first_name, last_name, role, is_active, is_verified, 
       mfa_enabled, last_login, created_at FROM users WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return done(null, false);
    }

    const user = result.rows[0];
    return done(null, user);

  } catch (error) {
    logger.error('Deserialize user error:', error);
    return done(error);
  }
});

module.exports = passport;