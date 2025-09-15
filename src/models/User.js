const { query, transaction } = require('../config/database');
const argon2 = require('argon2');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const logger = require('../config/logger');

class User {
  constructor(data) {
    Object.assign(this, data);
  }

  // Create a new user
  static async create(userData) {
    const {
      email,
      password,
      firstName,
      lastName,
      role = 'user',
      phone,
      dateOfBirth,
      gdprConsent = false
    } = userData;

    return await transaction(async (client) => {
      // Hash password with Argon2id
      const passwordHash = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: parseInt(process.env.ARGON2_MEMORY_COST) || 65536,
        timeCost: parseInt(process.env.ARGON2_TIME_COST) || 3,
        parallelism: parseInt(process.env.ARGON2_PARALLELISM) || 4,
        hashLength: 50
      });

      // Generate email verification token
      const emailVerificationToken = crypto.randomBytes(32).toString('hex');
      const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      const result = await client.query(`
        INSERT INTO users (
          email, password_hash, first_name, last_name, role, phone, date_of_birth,
          gdpr_consent, gdpr_consent_date, email_verification_token, email_verification_expires
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id, email, first_name, last_name, role, phone, date_of_birth, 
                  is_active, is_verified, mfa_enabled, created_at
      `, [
        email.toLowerCase(),
        passwordHash,
        firstName,
        lastName,
        role,
        phone,
        dateOfBirth,
        gdprConsent,
        gdprConsent ? new Date() : null,
        emailVerificationToken,
        emailVerificationExpires
      ]);

      // Insert email verification token
      await client.query(`
        INSERT INTO email_verification_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
      `, [result.rows[0].id, emailVerificationToken, emailVerificationExpires]);

      // Log user creation
      await this.logAuditEvent(client, result.rows[0].id, 'user_created', 'user', result.rows[0].id);

      const user = new User(result.rows[0]);
      user.emailVerificationToken = emailVerificationToken;
      return user;
    });
  }

  // Find user by ID
  static async findById(id) {
    const result = await query(`
      SELECT id, email, first_name, last_name, role, phone, date_of_birth,
             is_active, is_verified, mfa_enabled, mfa_secret, failed_login_attempts,
             locked_until, last_login, gdpr_consent, created_at, updated_at
      FROM users WHERE id = $1
    `, [id]);

    return result.rows.length > 0 ? new User(result.rows[0]) : null;
  }

  // Find user by email
  static async findByEmail(email) {
    const result = await query(`
      SELECT id, email, password_hash, first_name, last_name, role, phone, date_of_birth,
             is_active, is_verified, mfa_enabled, mfa_secret, failed_login_attempts,
             locked_until, last_login, gdpr_consent, created_at, updated_at
      FROM users WHERE email = $1
    `, [email.toLowerCase()]);

    return result.rows.length > 0 ? new User(result.rows[0]) : null;
  }

  // Update user
  async update(updateData) {
    const allowedFields = [
      'first_name', 'last_name', 'phone', 'date_of_birth', 'is_active',
      'is_verified', 'mfa_enabled', 'mfa_secret', 'failed_login_attempts',
      'locked_until', 'last_login'
    ];

    const fields = [];
    const values = [];
    let paramCount = 1;

    Object.keys(updateData).forEach(key => {
      if (allowedFields.includes(key) && updateData[key] !== undefined) {
        fields.push(`${key} = $${paramCount}`);
        values.push(updateData[key]);
        paramCount++;
      }
    });

    if (fields.length === 0) {
      throw new Error('No valid fields to update');
    }

    values.push(this.id);

    const result = await query(`
      UPDATE users SET ${fields.join(', ')}, updated_at = NOW()
      WHERE id = $${paramCount}
      RETURNING id, email, first_name, last_name, role, phone, date_of_birth,
                is_active, is_verified, mfa_enabled, last_login, created_at, updated_at
    `, values);

    if (result.rows.length > 0) {
      Object.assign(this, result.rows[0]);
    }

    return this;
  }

  // Change password
  async changePassword(newPassword) {
    const passwordHash = await argon2.hash(newPassword, {
      type: argon2.argon2id,
      memoryCost: parseInt(process.env.ARGON2_MEMORY_COST) || 65536,
      timeCost: parseInt(process.env.ARGON2_TIME_COST) || 3,
      parallelism: parseInt(process.env.ARGON2_PARALLELISM) || 4,
      hashLength: 50
    });

    await query(`
      UPDATE users SET password_hash = $1, updated_at = NOW()
      WHERE id = $2
    `, [passwordHash, this.id]);

    // Log password change
    await User.logAuditEvent(null, this.id, 'password_changed', 'user', this.id);

    return true;
  }

  // Verify password
  async verifyPassword(password) {
    if (!this.password_hash) {
      throw new Error('Password hash not loaded');
    }

    return await argon2.verify(this.password_hash, password);
  }

  // Enable/disable MFA
  async setMFA(enabled, secret = null) {
    const updateData = { mfa_enabled: enabled };
    
    if (enabled && secret) {
      // Encrypt the MFA secret
      const cipher = crypto.createCipher('aes-256-cbc', process.env.JWT_SECRET);
      let encrypted = cipher.update(secret, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      updateData.mfa_secret = encrypted;
    } else if (!enabled) {
      updateData.mfa_secret = null;
    }

    await this.update(updateData);

    // Log MFA change
    await User.logAuditEvent(null, this.id, enabled ? 'mfa_enabled' : 'mfa_disabled', 'user', this.id);

    return true;
  }

  // Get decrypted MFA secret
  getMFASecret() {
    if (!this.mfa_secret) {
      return null;
    }

    try {
      const decipher = crypto.createDecipher('aes-256-cbc', process.env.JWT_SECRET);
      let decrypted = decipher.update(this.mfa_secret, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      logger.error('Error decrypting MFA secret:', error);
      return null;
    }
  }

  // Verify email
  static async verifyEmail(token) {
    return await transaction(async (client) => {
      // Find valid token
      const tokenResult = await client.query(`
        SELECT user_id FROM email_verification_tokens
        WHERE token = $1 AND expires_at > NOW() AND verified_at IS NULL
      `, [token]);

      if (tokenResult.rows.length === 0) {
        throw new Error('Invalid or expired verification token');
      }

      const userId = tokenResult.rows[0].user_id;

      // Update user as verified
      await client.query(`
        UPDATE users SET is_verified = true, updated_at = NOW()
        WHERE id = $1
      `, [userId]);

      // Mark token as used
      await client.query(`
        UPDATE email_verification_tokens SET verified_at = NOW()
        WHERE token = $1
      `, [token]);

      // Log email verification
      await this.logAuditEvent(client, userId, 'email_verified', 'user', userId);

      return true;
    });
  }

  // Create password reset token
  static async createPasswordResetToken(email) {
    return await transaction(async (client) => {
      // Find user
      const userResult = await client.query(`
        SELECT id FROM users WHERE email = $1 AND is_active = true
      `, [email.toLowerCase()]);

      if (userResult.rows.length === 0) {
        throw new Error('User not found');
      }

      const userId = userResult.rows[0].id;
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Invalidate existing tokens
      await client.query(`
        UPDATE password_reset_tokens SET used_at = NOW()
        WHERE user_id = $1 AND used_at IS NULL
      `, [userId]);

      // Create new token
      await client.query(`
        INSERT INTO password_reset_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
      `, [userId, token, expiresAt]);

      // Log password reset request
      await this.logAuditEvent(client, userId, 'password_reset_requested', 'user', userId);

      return { token, userId };
    });
  }

  // Reset password with token
  static async resetPassword(token, newPassword) {
    return await transaction(async (client) => {
      // Find valid token
      const tokenResult = await client.query(`
        SELECT user_id FROM password_reset_tokens
        WHERE token = $1 AND expires_at > NOW() AND used_at IS NULL
      `, [token]);

      if (tokenResult.rows.length === 0) {
        throw new Error('Invalid or expired reset token');
      }

      const userId = tokenResult.rows[0].user_id;

      // Hash new password
      const passwordHash = await argon2.hash(newPassword, {
        type: argon2.argon2id,
        memoryCost: parseInt(process.env.ARGON2_MEMORY_COST) || 65536,
        timeCost: parseInt(process.env.ARGON2_TIME_COST) || 3,
        parallelism: parseInt(process.env.ARGON2_PARALLELISM) || 4,
        hashLength: 50
      });

      // Update password and reset failed attempts
      await client.query(`
        UPDATE users SET 
          password_hash = $1, 
          failed_login_attempts = 0,
          locked_until = NULL,
          updated_at = NOW()
        WHERE id = $2
      `, [passwordHash, userId]);

      // Mark token as used
      await client.query(`
        UPDATE password_reset_tokens SET used_at = NOW()
        WHERE token = $1
      `, [token]);

      // Log password reset
      await this.logAuditEvent(client, userId, 'password_reset', 'user', userId);

      return true;
    });
  }

  // Get user list with pagination
  static async getList(options = {}) {
    const {
      page = 1,
      limit = 20,
      sort = 'created_at',
      order = 'desc',
      role,
      isActive,
      isVerified
    } = options;

    const offset = (page - 1) * limit;
    const conditions = [];
    const values = [];
    let paramCount = 1;

    if (role) {
      conditions.push(`role = $${paramCount}`);
      values.push(role);
      paramCount++;
    }

    if (isActive !== undefined) {
      conditions.push(`is_active = $${paramCount}`);
      values.push(isActive);
      paramCount++;
    }

    if (isVerified !== undefined) {
      conditions.push(`is_verified = $${paramCount}`);
      values.push(isVerified);
      paramCount++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    
    values.push(limit, offset);

    const result = await query(`
      SELECT id, email, first_name, last_name, role, phone, date_of_birth,
             is_active, is_verified, mfa_enabled, last_login, created_at, updated_at
      FROM users
      ${whereClause}
      ORDER BY ${sort} ${order.toUpperCase()}
      LIMIT $${paramCount} OFFSET $${paramCount + 1}
    `, values);

    // Get total count
    const countResult = await query(`
      SELECT COUNT(*) as total FROM users ${whereClause}
    `, values.slice(0, -2));

    return {
      users: result.rows.map(row => new User(row)),
      total: parseInt(countResult.rows[0].total),
      page,
      limit,
      totalPages: Math.ceil(countResult.rows[0].total / limit)
    };
  }

  // Delete user (soft delete)
  async delete() {
    await query(`
      UPDATE users SET is_active = false, updated_at = NOW()
      WHERE id = $1
    `, [this.id]);

    // Log user deletion
    await User.logAuditEvent(null, this.id, 'user_deleted', 'user', this.id);

    this.is_active = false;
    return true;
  }

  // Hard delete user (for GDPR)
  async hardDelete() {
    return await transaction(async (client) => {
      // Delete all related data
      await client.query('DELETE FROM user_sessions WHERE user_id = $1', [this.id]);
      await client.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [this.id]);
      await client.query('DELETE FROM email_verification_tokens WHERE user_id = $1', [this.id]);
      await client.query('DELETE FROM file_uploads WHERE user_id = $1', [this.id]);
      await client.query('DELETE FROM gdpr_requests WHERE user_id = $1', [this.id]);
      await client.query('DELETE FROM user_permissions WHERE user_id = $1', [this.id]);
      await client.query('DELETE FROM blacklisted_tokens WHERE user_id = $1', [this.id]);
      await client.query('DELETE FROM provider_profiles WHERE user_id = $1', [this.id]);
      
      // Update audit logs to remove user reference
      await client.query('UPDATE audit_logs SET user_id = NULL WHERE user_id = $1', [this.id]);

      // Delete user
      await client.query('DELETE FROM users WHERE id = $1', [this.id]);

      // Log hard deletion (with null user_id)
      await this.logAuditEvent(client, null, 'user_hard_deleted', 'user', this.id);

      return true;
    });
  }

  // Log audit event
  static async logAuditEvent(client, userId, action, resourceType, resourceId, details = null, ipAddress = null) {
    const queryFn = client ? client.query.bind(client) : query;
    
    await queryFn(`
      INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, details)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [userId, action, resourceType, resourceId, ipAddress, details ? JSON.stringify(details) : null]);
  }

  // Export user data (GDPR)
  async exportData() {
    const userData = await query(`
      SELECT 
        id, email, first_name, last_name, role, phone, date_of_birth,
        is_active, is_verified, mfa_enabled, last_login, gdpr_consent,
        gdpr_consent_date, created_at, updated_at
      FROM users WHERE id = $1
    `, [this.id]);

    const providerData = await query(`
      SELECT * FROM provider_profiles WHERE user_id = $1
    `, [this.id]);

    const fileUploads = await query(`
      SELECT original_filename, mime_type, file_size, file_type, created_at
      FROM file_uploads WHERE user_id = $1
    `, [this.id]);

    const auditLogs = await query(`
      SELECT action, resource_type, ip_address, created_at
      FROM audit_logs WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 1000
    `, [this.id]);

    return {
      personal_data: userData.rows[0],
      provider_profile: providerData.rows[0] || null,
      file_uploads: fileUploads.rows,
      activity_log: auditLogs.rows,
      export_date: new Date().toISOString()
    };
  }

  // Convert to JSON (exclude sensitive fields)
  toJSON() {
    const { password_hash, mfa_secret, ...publicData } = this;
    return publicData;
  }
}

module.exports = User;