const multer = require('multer');
const { GridFSBucket } = require('mongodb');
const { getGridFSBucket } = require('../config/mongodb');
const { query } = require('../config/database');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const crypto = require('crypto');
const logger = require('../config/logger');

class FileService {
  constructor() {
    this.allowedMimeTypes = [
      'application/pdf',
      'image/jpeg',
      'image/jpg',
      'image/png',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    
    this.maxFileSize = parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024; // 5MB
  }

  // Create multer configuration for GridFS
  createMulterConfig() {
    const storage = multer.memoryStorage();

    const fileFilter = (req, file, cb) => {
      // Check file type
      if (!this.allowedMimeTypes.includes(file.mimetype)) {
        return cb(new Error(`File type ${file.mimetype} is not allowed`), false);
      }

      // Check file size
      if (file.size > this.maxFileSize) {
        return cb(new Error('File size exceeds maximum allowed size'), false);
      }

      cb(null, true);
    };

    return multer({
      storage,
      fileFilter,
      limits: {
        fileSize: this.maxFileSize,
        files: 5 // Maximum 5 files at once
      }
    });
  }

  // Upload file to GridFS
  async uploadFile(fileBuffer, filename, mimeType, userId, fileType = 'general') {
    try {
      const bucket = getGridFSBucket();
      const fileId = uuidv4();
      
      // Create upload stream
      const uploadStream = bucket.openUploadStream(filename, {
        id: fileId,
        metadata: {
          userId,
          fileType,
          originalName: filename,
          mimeType,
          uploadedAt: new Date()
        }
      });

      // Upload file
      await new Promise((resolve, reject) => {
        uploadStream.end(fileBuffer, (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });

      // Save file metadata to PostgreSQL
      const result = await query(`
        INSERT INTO file_uploads (
          user_id, original_filename, mime_type, file_size, mongodb_file_id, file_type
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, original_filename, mime_type, file_size, file_type, created_at
      `, [userId, filename, mimeType, fileBuffer.length, fileId, fileType]);

      logger.info('File uploaded successfully', {
        userId,
        filename,
        fileId,
        size: fileBuffer.length
      });

      return {
        id: result.rows[0].id,
        fileId,
        filename: result.rows[0].original_filename,
        mimeType: result.rows[0].mime_type,
        size: result.rows[0].file_size,
        fileType: result.rows[0].file_type,
        uploadedAt: result.rows[0].created_at
      };
    } catch (error) {
      logger.error('File upload failed:', error);
      throw error;
    }
  }

  // Get file from GridFS
  async getFile(fileId) {
    try {
      const bucket = getGridFSBucket();
      
      // Find file metadata
      const files = await bucket.find({ id: fileId }).toArray();
      if (files.length === 0) {
        throw new Error('File not found');
      }

      const file = files[0];
      
      // Create download stream
      const downloadStream = bucket.openDownloadStream(fileId);
      
      return {
        stream: downloadStream,
        metadata: file.metadata,
        filename: file.filename,
        contentType: file.metadata.mimeType
      };
    } catch (error) {
      logger.error('File retrieval failed:', error);
      throw error;
    }
  }

  // Download file as buffer
  async downloadFile(fileId) {
    try {
      const bucket = getGridFSBucket();
      
      // Find file metadata
      const files = await bucket.find({ id: fileId }).toArray();
      if (files.length === 0) {
        throw new Error('File not found');
      }

      const file = files[0];
      const downloadStream = bucket.openDownloadStream(fileId);
      
      // Convert stream to buffer
      const chunks = [];
      return new Promise((resolve, reject) => {
        downloadStream.on('data', (chunk) => chunks.push(chunk));
        downloadStream.on('error', reject);
        downloadStream.on('end', () => {
          resolve({
            buffer: Buffer.concat(chunks),
            metadata: file.metadata,
            filename: file.filename,
            contentType: file.metadata.mimeType
          });
        });
      });
    } catch (error) {
      logger.error('File download failed:', error);
      throw error;
    }
  }

  // Delete file from GridFS and database
  async deleteFile(fileId, userId) {
    try {
      const bucket = getGridFSBucket();

      // Verify user owns the file
      const result = await query(`
        SELECT mongodb_file_id FROM file_uploads 
        WHERE mongodb_file_id = $1 AND user_id = $2
      `, [fileId, userId]);

      if (result.rows.length === 0) {
        throw new Error('File not found or access denied');
      }

      // Delete from GridFS
      await bucket.delete(fileId);

      // Delete from database
      await query(`
        DELETE FROM file_uploads WHERE mongodb_file_id = $1
      `, [fileId]);

      logger.info('File deleted successfully', {
        userId,
        fileId
      });

      return true;
    } catch (error) {
      logger.error('File deletion failed:', error);
      throw error;
    }
  }

  // Get user's files
  async getUserFiles(userId, options = {}) {
    try {
      const {
        page = 1,
        limit = 20,
        fileType,
        sort = 'created_at',
        order = 'desc'
      } = options;

      const offset = (page - 1) * limit;
      const conditions = ['user_id = $1'];
      const values = [userId];
      let paramCount = 2;

      if (fileType) {
        conditions.push(`file_type = $${paramCount}`);
        values.push(fileType);
        paramCount++;
      }

      values.push(limit, offset);

      const result = await query(`
        SELECT id, original_filename, mime_type, file_size, mongodb_file_id, 
               file_type, is_verified, verified_at, created_at
        FROM file_uploads
        WHERE ${conditions.join(' AND ')}
        ORDER BY ${sort} ${order.toUpperCase()}
        LIMIT $${paramCount} OFFSET $${paramCount + 1}
      `, values);

      // Get total count
      const countResult = await query(`
        SELECT COUNT(*) as total FROM file_uploads WHERE ${conditions.join(' AND ')}
      `, values.slice(0, -2));

      return {
        files: result.rows,
        total: parseInt(countResult.rows[0].total),
        page,
        limit,
        totalPages: Math.ceil(countResult.rows[0].total / limit)
      };
    } catch (error) {
      logger.error('Get user files failed:', error);
      throw error;
    }
  }

  // Verify file (admin/provider verification)
  async verifyFile(fileId, verifiedBy) {
    try {
      const result = await query(`
        UPDATE file_uploads 
        SET is_verified = true, verified_at = NOW(), verified_by = $1
        WHERE mongodb_file_id = $2
        RETURNING id, user_id, original_filename
      `, [verifiedBy, fileId]);

      if (result.rows.length === 0) {
        throw new Error('File not found');
      }

      logger.info('File verified successfully', {
        fileId,
        verifiedBy,
        userId: result.rows[0].user_id
      });

      return result.rows[0];
    } catch (error) {
      logger.error('File verification failed:', error);
      throw error;
    }
  }

  // Generate secure file URL (with expiration)
  generateSecureFileUrl(fileId, expiresIn = 3600) {
    const timestamp = Date.now() + (expiresIn * 1000);
    const signature = crypto
      .createHmac('sha256', process.env.JWT_SECRET)
      .update(`${fileId}:${timestamp}`)
      .digest('hex');

    return {
      url: `/api/v1/files/${fileId}?expires=${timestamp}&signature=${signature}`,
      expiresAt: new Date(timestamp)
    };
  }

  // Validate secure file URL
  validateSecureFileUrl(fileId, expires, signature) {
    try {
      const now = Date.now();
      const expireTime = parseInt(expires);

      // Check if URL has expired
      if (now > expireTime) {
        return false;
      }

      // Verify signature
      const expectedSignature = crypto
        .createHmac('sha256', process.env.JWT_SECRET)
        .update(`${fileId}:${expires}`)
        .digest('hex');

      return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex')
      );
    } catch (error) {
      logger.error('URL validation failed:', error);
      return false;
    }
  }

  // Scan file for viruses (placeholder for future implementation)
  async scanFile(fileBuffer, filename) {
    // In production, integrate with antivirus service like ClamAV
    logger.info('File scanned (placeholder)', { filename });
    return { clean: true, threats: [] };
  }

  // Get file statistics
  async getFileStatistics() {
    try {
      const result = await query(`
        SELECT 
          COUNT(*) as total_files,
          SUM(file_size) as total_size,
          COUNT(CASE WHEN is_verified = true THEN 1 END) as verified_files,
          COUNT(CASE WHEN file_type = 'license' THEN 1 END) as license_files,
          COUNT(CASE WHEN file_type = 'certificate' THEN 1 END) as certificate_files,
          COUNT(CASE WHEN file_type = 'identification' THEN 1 END) as identification_files,
          AVG(file_size) as average_size
        FROM file_uploads
      `);

      return result.rows[0];
    } catch (error) {
      logger.error('Get file statistics failed:', error);
      throw error;
    }
  }

  // Clean up old files (for GDPR compliance)
  async cleanupOldFiles(daysOld = 365) {
    try {
      const bucket = getGridFSBucket();
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysOld);

      // Get old files
      const oldFiles = await query(`
        SELECT mongodb_file_id FROM file_uploads
        WHERE created_at < $1
      `, [cutoffDate]);

      let deletedCount = 0;

      for (const file of oldFiles.rows) {
        try {
          // Delete from GridFS
          await bucket.delete(file.mongodb_file_id);
          
          // Delete from database
          await query(`
            DELETE FROM file_uploads WHERE mongodb_file_id = $1
          `, [file.mongodb_file_id]);

          deletedCount++;
        } catch (error) {
          logger.error('Failed to delete old file:', {
            fileId: file.mongodb_file_id,
            error: error.message
          });
        }
      }

      logger.info('Old files cleanup completed', {
        daysOld,
        deletedCount,
        totalFound: oldFiles.rows.length
      });

      return { deletedCount, totalFound: oldFiles.rows.length };
    } catch (error) {
      logger.error('File cleanup failed:', error);
      throw error;
    }
  }

  // Validate file integrity
  async validateFileIntegrity(fileId) {
    try {
      const bucket = getGridFSBucket();
      
      // Check if file exists in GridFS
      const files = await bucket.find({ id: fileId }).toArray();
      if (files.length === 0) {
        return { valid: false, reason: 'File not found in GridFS' };
      }

      // Check if metadata exists in database
      const dbResult = await query(`
        SELECT id FROM file_uploads WHERE mongodb_file_id = $1
      `, [fileId]);

      if (dbResult.rows.length === 0) {
        return { valid: false, reason: 'File metadata not found in database' };
      }

      return { valid: true };
    } catch (error) {
      logger.error('File integrity validation failed:', error);
      return { valid: false, reason: error.message };
    }
  }
}

module.exports = new FileService();