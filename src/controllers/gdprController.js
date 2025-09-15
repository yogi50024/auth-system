const User = require('../models/User');
const { query } = require('../config/database');
const { catchAsync, AppError } = require('../middleware/errorHandler');
const logger = require('../config/logger');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');

class GDPRController {
  // Request data export
  static requestDataExport = catchAsync(async (req, res) => {
    const userId = req.user.id;

    // Check if user has pending export request
    const existingRequest = await query(`
      SELECT id FROM gdpr_requests 
      WHERE user_id = $1 AND request_type = 'export' AND status IN ('pending', 'processing')
    `, [userId]);

    if (existingRequest.rows.length > 0) {
      throw new AppError('You already have a pending data export request', 400);
    }

    // Create export request
    const result = await query(`
      INSERT INTO gdpr_requests (user_id, request_type, status)
      VALUES ($1, 'export', 'pending')
      RETURNING id, requested_at
    `, [userId]);

    // Process export asynchronously
    this.processDataExport(userId, result.rows[0].id);

    res.status(202).json({
      status: 'success',
      message: 'Data export request submitted. You will receive an email when your data is ready for download.',
      data: {
        requestId: result.rows[0].id,
        requestedAt: result.rows[0].requested_at
      }
    });
  });

  // Process data export (background job)
  static async processDataExport(userId, requestId) {
    try {
      // Update status to processing
      await query(`
        UPDATE gdpr_requests SET status = 'processing', processed_at = NOW()
        WHERE id = $1
      `, [requestId]);

      // Get user data
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Export user data
      const exportData = await user.exportData();

      // Create export file
      const exportFileName = `user_data_export_${userId}_${Date.now()}.json`;
      const exportPath = path.join(__dirname, '../../exports', exportFileName);

      // Ensure exports directory exists
      await fs.mkdir(path.dirname(exportPath), { recursive: true });

      // Write export file
      await fs.writeFile(exportPath, JSON.stringify(exportData, null, 2));

      // Update request as completed
      await query(`
        UPDATE gdpr_requests 
        SET status = 'completed', completed_at = NOW(), export_file_path = $1
        WHERE id = $2
      `, [exportPath, requestId]);

      // Generate secure download URL
      const downloadToken = uuidv4();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      // Store download token (in practice, use Redis for this)
      await query(`
        INSERT INTO export_download_tokens (request_id, token, expires_at)
        VALUES ($1, $2, $3)
      `, [requestId, downloadToken, expiresAt]);

      // Send email with download link
      const downloadUrl = `${process.env.FRONTEND_URL}/download-export?token=${downloadToken}`;
      
      try {
        const emailService = require('../services/emailService');
        await emailService.sendGDPRExportEmail(user, downloadUrl);
      } catch (emailError) {
        logger.error('Failed to send GDPR export email:', emailError);
      }

      logger.info('Data export completed successfully', {
        userId,
        requestId,
        exportPath
      });

    } catch (error) {
      logger.error('Data export failed:', error);
      
      // Update request as failed
      await query(`
        UPDATE gdpr_requests 
        SET status = 'failed', notes = $1
        WHERE id = $2
      `, [error.message, requestId]);
    }
  }

  // Download exported data
  static downloadExport = catchAsync(async (req, res) => {
    const { token } = req.query;

    if (!token) {
      throw new AppError('Download token is required', 400);
    }

    // Verify download token
    const tokenResult = await query(`
      SELECT edt.request_id, gr.export_file_path, gr.user_id
      FROM export_download_tokens edt
      JOIN gdpr_requests gr ON edt.request_id = gr.id
      WHERE edt.token = $1 AND edt.expires_at > NOW()
    `, [token]);

    if (tokenResult.rows.length === 0) {
      throw new AppError('Invalid or expired download token', 400);
    }

    const { export_file_path, user_id } = tokenResult.rows[0];

    // Verify file exists
    try {
      await fs.access(export_file_path);
    } catch (error) {
      throw new AppError('Export file not found', 404);
    }

    // Read and send file
    const fileContent = await fs.readFile(export_file_path);
    const fileName = `user_data_export_${user_id}.json`;

    res.set({
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="${fileName}"`,
      'Content-Length': fileContent.length
    });

    res.send(fileContent);

    // Log download
    await User.logAuditEvent(
      null,
      user_id,
      'gdpr_export_downloaded',
      'gdpr_request',
      tokenResult.rows[0].request_id,
      null,
      req.ip
    );
  });

  // Request account deletion
  static requestAccountDeletion = catchAsync(async (req, res) => {
    const userId = req.user.id;
    const { confirmPassword } = req.body;

    // Verify password
    const user = await User.findByEmail(req.user.email);
    const isValidPassword = await user.verifyPassword(confirmPassword);
    
    if (!isValidPassword) {
      throw new AppError('Invalid password', 400);
    }

    // Check if user has pending deletion request
    const existingRequest = await query(`
      SELECT id FROM gdpr_requests 
      WHERE user_id = $1 AND request_type = 'delete' AND status IN ('pending', 'processing')
    `, [userId]);

    if (existingRequest.rows.length > 0) {
      throw new AppError('You already have a pending account deletion request', 400);
    }

    // Create deletion request
    const result = await query(`
      INSERT INTO gdpr_requests (user_id, request_type, status)
      VALUES ($1, 'delete', 'pending')
      RETURNING id, requested_at
    `, [userId]);

    // Log deletion request
    await User.logAuditEvent(
      null,
      userId,
      'gdpr_deletion_requested',
      'gdpr_request',
      result.rows[0].id,
      null,
      req.ip
    );

    res.status(202).json({
      status: 'success',
      message: 'Account deletion request submitted. Your account will be permanently deleted within 30 days unless you cancel the request.',
      data: {
        requestId: result.rows[0].id,
        requestedAt: result.rows[0].requested_at,
        deletionDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      }
    });
  });

  // Cancel account deletion request
  static cancelAccountDeletion = catchAsync(async (req, res) => {
    const userId = req.user.id;

    // Find pending deletion request
    const result = await query(`
      UPDATE gdpr_requests 
      SET status = 'cancelled', notes = 'Cancelled by user'
      WHERE user_id = $1 AND request_type = 'delete' AND status = 'pending'
      RETURNING id
    `, [userId]);

    if (result.rows.length === 0) {
      throw new AppError('No pending deletion request found', 404);
    }

    // Log cancellation
    await User.logAuditEvent(
      null,
      userId,
      'gdpr_deletion_cancelled',
      'gdpr_request',
      result.rows[0].id,
      null,
      req.ip
    );

    res.status(200).json({
      status: 'success',
      message: 'Account deletion request cancelled successfully'
    });
  });

  // Get GDPR requests for user
  static getGDPRRequests = catchAsync(async (req, res) => {
    const userId = req.user.id;

    const result = await query(`
      SELECT id, request_type, status, requested_at, processed_at, completed_at, notes
      FROM gdpr_requests
      WHERE user_id = $1
      ORDER BY requested_at DESC
    `, [userId]);

    res.status(200).json({
      status: 'success',
      data: {
        requests: result.rows
      }
    });
  });

  // Get all GDPR requests (admin only)
  static getAllGDPRRequests = catchAsync(async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    const { requestType, status } = req.query;

    const conditions = [];
    const values = [];
    let paramCount = 1;

    if (requestType) {
      conditions.push(`gr.request_type = $${paramCount}`);
      values.push(requestType);
      paramCount++;
    }

    if (status) {
      conditions.push(`gr.status = $${paramCount}`);
      values.push(status);
      paramCount++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    values.push(limit, offset);

    const result = await query(`
      SELECT 
        gr.id, gr.request_type, gr.status, gr.requested_at, gr.processed_at, 
        gr.completed_at, gr.notes,
        u.email, u.first_name, u.last_name
      FROM gdpr_requests gr
      JOIN users u ON gr.user_id = u.id
      ${whereClause}
      ORDER BY gr.requested_at DESC
      LIMIT $${paramCount} OFFSET $${paramCount + 1}
    `, values);

    const countResult = await query(`
      SELECT COUNT(*) as total 
      FROM gdpr_requests gr
      JOIN users u ON gr.user_id = u.id
      ${whereClause}
    `, values.slice(0, -2));

    res.status(200).json({
      status: 'success',
      data: {
        requests: result.rows,
        pagination: {
          page,
          limit,
          total: parseInt(countResult.rows[0].total),
          totalPages: Math.ceil(countResult.rows[0].total / limit)
        }
      }
    });
  });

  // Process account deletion (admin only)
  static processAccountDeletion = catchAsync(async (req, res) => {
    const { requestId } = req.params;

    // Get deletion request
    const requestResult = await query(`
      SELECT user_id FROM gdpr_requests 
      WHERE id = $1 AND request_type = 'delete' AND status = 'pending'
    `, [requestId]);

    if (requestResult.rows.length === 0) {
      throw new AppError('Deletion request not found or already processed', 404);
    }

    const userId = requestResult.rows[0].user_id;

    // Get user
    const user = await User.findById(userId);
    if (!user) {
      throw new AppError('User not found', 404);
    }

    // Update request status
    await query(`
      UPDATE gdpr_requests 
      SET status = 'processing', processed_at = NOW()
      WHERE id = $1
    `, [requestId]);

    try {
      // Hard delete user and all associated data
      await user.hardDelete();

      // Update request as completed
      await query(`
        UPDATE gdpr_requests 
        SET status = 'completed', completed_at = NOW()
        WHERE id = $1
      `, [requestId]);

      logger.info('Account deletion completed', {
        userId,
        requestId,
        processedBy: req.user.id
      });

      res.status(200).json({
        status: 'success',
        message: 'Account deletion completed successfully'
      });

    } catch (error) {
      // Update request as failed
      await query(`
        UPDATE gdpr_requests 
        SET status = 'failed', notes = $1
        WHERE id = $2
      `, [error.message, requestId]);

      logger.error('Account deletion failed:', error);
      throw error;
    }
  });

  // Get GDPR compliance status
  static getComplianceStatus = catchAsync(async (req, res) => {
    const userId = req.user.id;

    const user = await User.findById(userId);
    if (!user) {
      throw new AppError('User not found', 404);
    }

    // Get active requests
    const activeRequests = await query(`
      SELECT request_type, status, requested_at
      FROM gdpr_requests
      WHERE user_id = $1 AND status IN ('pending', 'processing')
    `, [userId]);

    // Calculate data retention date
    const retentionDays = parseInt(process.env.GDPR_DATA_RETENTION_DAYS) || 365;
    const dataRetentionDate = new Date(user.created_at);
    dataRetentionDate.setDate(dataRetentionDate.getDate() + retentionDays);

    res.status(200).json({
      status: 'success',
      data: {
        gdprConsent: user.gdpr_consent,
        gdprConsentDate: user.gdpr_consent_date,
        dataRetentionDate,
        activeRequests: activeRequests.rows,
        rights: {
          dataPortability: true,
          rectification: true,
          erasure: true,
          restrictProcessing: true,
          objectProcessing: true
        }
      }
    });
  });

  // Update GDPR consent
  static updateGDPRConsent = catchAsync(async (req, res) => {
    const { consent } = req.body;
    const userId = req.user.id;

    if (typeof consent !== 'boolean') {
      throw new AppError('Consent must be a boolean value', 400);
    }

    const user = await User.findById(userId);
    if (!user) {
      throw new AppError('User not found', 404);
    }

    await query(`
      UPDATE users 
      SET gdpr_consent = $1, gdpr_consent_date = NOW(), updated_at = NOW()
      WHERE id = $2
    `, [consent, userId]);

    // Log consent update
    await User.logAuditEvent(
      null,
      userId,
      'gdpr_consent_updated',
      'user',
      userId,
      { consent },
      req.ip
    );

    res.status(200).json({
      status: 'success',
      message: 'GDPR consent updated successfully',
      data: {
        consent,
        consentDate: new Date()
      }
    });
  });
}

module.exports = GDPRController;