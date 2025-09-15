const User = require('../models/User');
const { catchAsync, AppError } = require('../middleware/errorHandler');
const logger = require('../config/logger');

class UserController {
  // Get user list (admin only)
  static getUsers = catchAsync(async (req, res) => {
    const options = {
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 20,
      sort: req.query.sort || 'created_at',
      order: req.query.order || 'desc',
      role: req.query.role,
      isActive: req.query.isActive !== undefined ? req.query.isActive === 'true' : undefined,
      isVerified: req.query.isVerified !== undefined ? req.query.isVerified === 'true' : undefined
    };

    const result = await User.getList(options);

    res.status(200).json({
      status: 'success',
      data: {
        users: result.users,
        pagination: {
          page: result.page,
          limit: result.limit,
          total: result.total,
          totalPages: result.totalPages
        }
      }
    });
  });

  // Get user by ID
  static getUserById = catchAsync(async (req, res) => {
    const { id } = req.params;
    const user = await User.findById(id);

    if (!user) {
      throw new AppError('User not found', 404);
    }

    res.status(200).json({
      status: 'success',
      data: {
        user: user.toJSON()
      }
    });
  });

  // Update user profile
  static updateProfile = catchAsync(async (req, res) => {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      throw new AppError('User not found', 404);
    }

    const allowedUpdates = ['first_name', 'last_name', 'phone', 'date_of_birth'];
    const updates = {};

    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    if (Object.keys(updates).length === 0) {
      throw new AppError('No valid updates provided', 400);
    }

    await user.update(updates);

    // Log profile update
    await User.logAuditEvent(
      null,
      req.user.id,
      'profile_updated',
      'user',
      req.user.id,
      { updatedFields: Object.keys(updates) },
      req.ip
    );

    res.status(200).json({
      status: 'success',
      message: 'Profile updated successfully',
      data: {
        user: user.toJSON()
      }
    });
  });

  // Update user (admin only)
  static updateUser = catchAsync(async (req, res) => {
    const { id } = req.params;
    const user = await User.findById(id);

    if (!user) {
      throw new AppError('User not found', 404);
    }

    const allowedUpdates = [
      'first_name', 'last_name', 'phone', 'date_of_birth',
      'is_active', 'is_verified', 'role'
    ];
    
    const updates = {};

    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    if (Object.keys(updates).length === 0) {
      throw new AppError('No valid updates provided', 400);
    }

    await user.update(updates);

    // Log admin update
    await User.logAuditEvent(
      null,
      req.user.id,
      'user_updated_by_admin',
      'user',
      id,
      { 
        updatedFields: Object.keys(updates),
        adminId: req.user.id
      },
      req.ip
    );

    res.status(200).json({
      status: 'success',
      message: 'User updated successfully',
      data: {
        user: user.toJSON()
      }
    });
  });

  // Deactivate user (soft delete)
  static deactivateUser = catchAsync(async (req, res) => {
    const { id } = req.params;
    const user = await User.findById(id);

    if (!user) {
      throw new AppError('User not found', 404);
    }

    if (!user.is_active) {
      throw new AppError('User is already deactivated', 400);
    }

    await user.delete();

    // Log deactivation
    await User.logAuditEvent(
      null,
      req.user.id,
      'user_deactivated',
      'user',
      id,
      { deactivatedBy: req.user.id },
      req.ip
    );

    res.status(200).json({
      status: 'success',
      message: 'User deactivated successfully'
    });
  });

  // Reactivate user
  static reactivateUser = catchAsync(async (req, res) => {
    const { id } = req.params;
    const user = await User.findById(id);

    if (!user) {
      throw new AppError('User not found', 404);
    }

    if (user.is_active) {
      throw new AppError('User is already active', 400);
    }

    await user.update({ is_active: true });

    // Log reactivation
    await User.logAuditEvent(
      null,
      req.user.id,
      'user_reactivated',
      'user',
      id,
      { reactivatedBy: req.user.id },
      req.ip
    );

    res.status(200).json({
      status: 'success',
      message: 'User reactivated successfully',
      data: {
        user: user.toJSON()
      }
    });
  });

  // Get user activity/audit logs
  static getUserActivity = catchAsync(async (req, res) => {
    const { id } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    // Verify user exists
    const user = await User.findById(id);
    if (!user) {
      throw new AppError('User not found', 404);
    }

    // Check permissions (user can only see their own activity, admins can see any)
    if (req.user.role !== 'admin' && req.user.id !== id) {
      throw new AppError('Access denied', 403);
    }

    const { query } = require('../config/database');
    
    const result = await query(`
      SELECT action, resource_type, resource_id, ip_address, details, created_at
      FROM audit_logs
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
    `, [id, limit, offset]);

    const countResult = await query(`
      SELECT COUNT(*) as total FROM audit_logs WHERE user_id = $1
    `, [id]);

    res.status(200).json({
      status: 'success',
      data: {
        activities: result.rows,
        pagination: {
          page,
          limit,
          total: parseInt(countResult.rows[0].total),
          totalPages: Math.ceil(countResult.rows[0].total / limit)
        }
      }
    });
  });

  // Get user statistics (admin only)
  static getUserStatistics = catchAsync(async (req, res) => {
    const { query } = require('../config/database');
    
    const result = await query(`
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN is_active = true THEN 1 END) as active_users,
        COUNT(CASE WHEN is_verified = true THEN 1 END) as verified_users,
        COUNT(CASE WHEN role = 'user' THEN 1 END) as regular_users,
        COUNT(CASE WHEN role = 'provider' THEN 1 END) as providers,
        COUNT(CASE WHEN role = 'admin' THEN 1 END) as admins,
        COUNT(CASE WHEN mfa_enabled = true THEN 1 END) as mfa_users,
        COUNT(CASE WHEN created_at >= NOW() - INTERVAL '30 days' THEN 1 END) as new_users_30d,
        COUNT(CASE WHEN last_login >= NOW() - INTERVAL '30 days' THEN 1 END) as active_users_30d
      FROM users
    `);

    res.status(200).json({
      status: 'success',
      data: {
        statistics: result.rows[0]
      }
    });
  });

  // Search users
  static searchUsers = catchAsync(async (req, res) => {
    const { q, role, isActive, isVerified } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    if (!q || q.trim().length < 2) {
      throw new AppError('Search query must be at least 2 characters', 400);
    }

    const { query } = require('../config/database');
    
    const conditions = [
      "(first_name ILIKE $1 OR last_name ILIKE $1 OR email ILIKE $1)"
    ];
    const values = [`%${q.trim()}%`];
    let paramCount = 2;

    if (role) {
      conditions.push(`role = $${paramCount}`);
      values.push(role);
      paramCount++;
    }

    if (isActive !== undefined) {
      conditions.push(`is_active = $${paramCount}`);
      values.push(isActive === 'true');
      paramCount++;
    }

    if (isVerified !== undefined) {
      conditions.push(`is_verified = $${paramCount}`);
      values.push(isVerified === 'true');
      paramCount++;
    }

    values.push(limit, offset);

    const result = await query(`
      SELECT id, email, first_name, last_name, role, phone,
             is_active, is_verified, mfa_enabled, last_login, created_at
      FROM users
      WHERE ${conditions.join(' AND ')}
      ORDER BY created_at DESC
      LIMIT $${paramCount} OFFSET $${paramCount + 1}
    `, values);

    const countResult = await query(`
      SELECT COUNT(*) as total FROM users WHERE ${conditions.join(' AND ')}
    `, values.slice(0, -2));

    res.status(200).json({
      status: 'success',
      data: {
        users: result.rows,
        pagination: {
          page,
          limit,
          total: parseInt(countResult.rows[0].total),
          totalPages: Math.ceil(countResult.rows[0].total / limit)
        }
      }
    });
  });

  // Delete user account (self-deletion or admin)
  static deleteAccount = catchAsync(async (req, res) => {
    const { id } = req.params;
    const { confirmPassword } = req.body;

    // Check permissions
    if (req.user.role !== 'admin' && req.user.id !== id) {
      throw new AppError('Access denied', 403);
    }

    const user = await User.findById(id);
    if (!user) {
      throw new AppError('User not found', 404);
    }

    // If user is deleting their own account, require password confirmation
    if (req.user.id === id && confirmPassword) {
      const userWithPassword = await User.findByEmail(user.email);
      const isValidPassword = await userWithPassword.verifyPassword(confirmPassword);
      
      if (!isValidPassword) {
        throw new AppError('Invalid password', 400);
      }
    }

    await user.delete();

    // Log account deletion
    await User.logAuditEvent(
      null,
      req.user.id,
      'account_deleted',
      'user',
      id,
      { 
        selfDeletion: req.user.id === id,
        deletedBy: req.user.id
      },
      req.ip
    );

    res.status(200).json({
      status: 'success',
      message: 'Account deleted successfully'
    });
  });
}

module.exports = UserController;