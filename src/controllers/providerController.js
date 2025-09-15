const Provider = require('../models/Provider');
const User = require('../models/User');
const fileService = require('../services/fileService');
const emailService = require('../services/emailService');
const { catchAsync, AppError } = require('../middleware/errorHandler');
const logger = require('../config/logger');

class ProviderController {
  // Register as provider
  static registerProvider = catchAsync(async (req, res) => {
    const {
      businessName,
      businessType,
      licenseNumber,
      taxId,
      businessAddress,
      website,
      description
    } = req.body;

    // Check if user already has a provider profile
    const existingProvider = await Provider.findByUserId(req.user.id);
    if (existingProvider) {
      throw new AppError('Provider profile already exists', 400);
    }

    const provider = await Provider.create(req.user.id, {
      businessName,
      businessType,
      licenseNumber,
      taxId,
      businessAddress,
      website,
      description
    });

    res.status(201).json({
      status: 'success',
      message: 'Provider registration submitted successfully. Your application is pending review.',
      data: {
        provider: provider.toJSON()
      }
    });
  });

  // Get provider profile
  static getProviderProfile = catchAsync(async (req, res) => {
    const provider = await Provider.findByUserId(req.user.id);
    
    if (!provider) {
      throw new AppError('Provider profile not found', 404);
    }

    res.status(200).json({
      status: 'success',
      data: {
        provider: provider.toJSON()
      }
    });
  });

  // Update provider profile
  static updateProviderProfile = catchAsync(async (req, res) => {
    const provider = await Provider.findByUserId(req.user.id);
    
    if (!provider) {
      throw new AppError('Provider profile not found', 404);
    }

    const allowedUpdates = [
      'businessName', 'businessType', 'licenseNumber', 'taxId',
      'businessAddress', 'website', 'description'
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

    await provider.update(updates);

    res.status(200).json({
      status: 'success',
      message: 'Provider profile updated successfully',
      data: {
        provider: provider.toJSON()
      }
    });
  });

  // Get all providers (admin only)
  static getProviders = catchAsync(async (req, res) => {
    const options = {
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 20,
      sort: req.query.sort || 'created_at',
      order: req.query.order || 'desc',
      status: req.query.status,
      businessType: req.query.businessType,
      search: req.query.search
    };

    const result = await Provider.getList(options);

    res.status(200).json({
      status: 'success',
      data: {
        providers: result.providers,
        pagination: {
          page: result.page,
          limit: result.limit,
          total: result.total,
          totalPages: result.totalPages
        }
      }
    });
  });

  // Get provider by ID (admin only)
  static getProviderById = catchAsync(async (req, res) => {
    const { id } = req.params;
    const provider = await Provider.findById(id);

    if (!provider) {
      throw new AppError('Provider not found', 404);
    }

    res.status(200).json({
      status: 'success',
      data: {
        provider: provider.toJSON()
      }
    });
  });

  // Verify provider (admin only)
  static verifyProvider = catchAsync(async (req, res) => {
    const { id } = req.params;
    const { verificationDocuments } = req.body;

    const provider = await Provider.findById(id);
    if (!provider) {
      throw new AppError('Provider not found', 404);
    }

    if (provider.status !== 'pending') {
      throw new AppError('Provider is not in pending status', 400);
    }

    await provider.verify(req.user.id, verificationDocuments);

    // Send approval email
    try {
      await emailService.sendProviderVerificationEmail(provider, 'approved');
    } catch (error) {
      logger.error('Failed to send provider approval email:', error);
    }

    res.status(200).json({
      status: 'success',
      message: 'Provider verified successfully',
      data: {
        provider: provider.toJSON()
      }
    });
  });

  // Reject provider (admin only)
  static rejectProvider = catchAsync(async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;

    if (!reason || reason.trim().length === 0) {
      throw new AppError('Rejection reason is required', 400);
    }

    const provider = await Provider.findById(id);
    if (!provider) {
      throw new AppError('Provider not found', 404);
    }

    if (provider.status !== 'pending') {
      throw new AppError('Provider is not in pending status', 400);
    }

    await provider.reject(req.user.id, reason);

    // Send rejection email
    try {
      await emailService.sendProviderVerificationEmail(provider, 'rejected', reason);
    } catch (error) {
      logger.error('Failed to send provider rejection email:', error);
    }

    res.status(200).json({
      status: 'success',
      message: 'Provider rejected successfully',
      data: {
        provider: provider.toJSON()
      }
    });
  });

  // Suspend provider (admin only)
  static suspendProvider = catchAsync(async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;

    if (!reason || reason.trim().length === 0) {
      throw new AppError('Suspension reason is required', 400);
    }

    const provider = await Provider.findById(id);
    if (!provider) {
      throw new AppError('Provider not found', 404);
    }

    if (provider.status !== 'active') {
      throw new AppError('Provider is not active', 400);
    }

    await provider.suspend(req.user.id, reason);

    // Send suspension email
    try {
      await emailService.sendProviderVerificationEmail(provider, 'suspended', reason);
    } catch (error) {
      logger.error('Failed to send provider suspension email:', error);
    }

    res.status(200).json({
      status: 'success',
      message: 'Provider suspended successfully',
      data: {
        provider: provider.toJSON()
      }
    });
  });

  // Reactivate provider (admin only)
  static reactivateProvider = catchAsync(async (req, res) => {
    const { id } = req.params;

    const provider = await Provider.findById(id);
    if (!provider) {
      throw new AppError('Provider not found', 404);
    }

    if (provider.status !== 'suspended') {
      throw new AppError('Provider is not suspended', 400);
    }

    await provider.reactivate(req.user.id);

    res.status(200).json({
      status: 'success',
      message: 'Provider reactivated successfully',
      data: {
        provider: provider.toJSON()
      }
    });
  });

  // Upload provider documents
  static uploadDocuments = catchAsync(async (req, res) => {
    const provider = await Provider.findByUserId(req.user.id);
    
    if (!provider) {
      throw new AppError('Provider profile not found', 404);
    }

    if (!req.files || req.files.length === 0) {
      throw new AppError('No files uploaded', 400);
    }

    const uploadedFiles = [];

    for (const file of req.files) {
      try {
        const uploadResult = await fileService.uploadFile(
          file.buffer,
          file.originalname,
          file.mimetype,
          req.user.id,
          req.body.fileType || 'verification'
        );

        // Add to provider verification documents
        await provider.addVerificationDocument({
          filename: uploadResult.filename,
          originalName: file.originalname,
          mimeType: file.mimetype,
          size: file.size,
          type: req.body.fileType || 'verification'
        });

        uploadedFiles.push(uploadResult);
      } catch (error) {
        logger.error('File upload failed:', error);
        throw new AppError(`Failed to upload ${file.originalname}: ${error.message}`, 400);
      }
    }

    res.status(200).json({
      status: 'success',
      message: 'Documents uploaded successfully',
      data: {
        uploadedFiles
      }
    });
  });

  // Get provider documents
  static getProviderDocuments = catchAsync(async (req, res) => {
    let provider;
    
    if (req.user.role === 'admin') {
      // Admin can view any provider's documents
      const { providerId } = req.params;
      provider = await Provider.findById(providerId);
    } else {
      // Provider can only view their own documents
      provider = await Provider.findByUserId(req.user.id);
    }

    if (!provider) {
      throw new AppError('Provider not found', 404);
    }

    const documents = provider.verification_documents || [];

    res.status(200).json({
      status: 'success',
      data: {
        documents
      }
    });
  });

  // Download provider document
  static downloadDocument = catchAsync(async (req, res) => {
    const { documentId } = req.params;
    
    let provider;
    if (req.user.role === 'admin') {
      // Find provider by document (admin access)
      const { query } = require('../config/database');
      const result = await query(`
        SELECT pp.id FROM provider_profiles pp
        WHERE pp.verification_documents::jsonb @> '[{"id": "${documentId}"}]'
      `);
      
      if (result.rows.length === 0) {
        throw new AppError('Document not found', 404);
      }
      
      provider = await Provider.findById(result.rows[0].id);
    } else {
      // Provider can only download their own documents
      provider = await Provider.findByUserId(req.user.id);
      if (!provider) {
        throw new AppError('Provider profile not found', 404);
      }
      
      const documents = provider.verification_documents || [];
      const document = documents.find(doc => doc.id === documentId);
      
      if (!document) {
        throw new AppError('Document not found', 404);
      }
    }

    // Get file from MongoDB GridFS
    const fileData = await fileService.downloadFile(documentId);

    res.set({
      'Content-Type': fileData.contentType,
      'Content-Disposition': `attachment; filename="${fileData.filename}"`
    });

    res.send(fileData.buffer);
  });

  // Delete provider document
  static deleteDocument = catchAsync(async (req, res) => {
    const { documentId } = req.params;
    
    const provider = await Provider.findByUserId(req.user.id);
    if (!provider) {
      throw new AppError('Provider profile not found', 404);
    }

    const documents = provider.verification_documents || [];
    const document = documents.find(doc => doc.id === documentId);
    
    if (!document) {
      throw new AppError('Document not found', 404);
    }

    // Delete from GridFS
    await fileService.deleteFile(documentId, req.user.id);

    // Remove from provider documents
    await provider.removeVerificationDocument(documentId);

    res.status(200).json({
      status: 'success',
      message: 'Document deleted successfully'
    });
  });

  // Get provider statistics (admin only)
  static getProviderStatistics = catchAsync(async (req, res) => {
    const statistics = await Provider.getStatistics();

    res.status(200).json({
      status: 'success',
      data: {
        statistics
      }
    });
  });

  // Get pending verifications count (admin only)
  static getPendingVerifications = catchAsync(async (req, res) => {
    const count = await Provider.getPendingVerificationsCount();

    res.status(200).json({
      status: 'success',
      data: {
        pendingCount: count
      }
    });
  });

  // Search providers
  static searchProviders = catchAsync(async (req, res) => {
    const { q, status, businessType } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;

    if (!q || q.trim().length < 2) {
      throw new AppError('Search query must be at least 2 characters', 400);
    }

    const options = {
      page,
      limit,
      search: q.trim(),
      status,
      businessType
    };

    const result = await Provider.getList(options);

    res.status(200).json({
      status: 'success',
      data: {
        providers: result.providers,
        pagination: {
          page: result.page,
          limit: result.limit,
          total: result.total,
          totalPages: result.totalPages
        }
      }
    });
  });

  // Delete provider profile
  static deleteProviderProfile = catchAsync(async (req, res) => {
    const provider = await Provider.findByUserId(req.user.id);
    
    if (!provider) {
      throw new AppError('Provider profile not found', 404);
    }

    if (provider.status === 'active') {
      throw new AppError('Cannot delete active provider profile. Please contact support.', 400);
    }

    await provider.delete();

    res.status(200).json({
      status: 'success',
      message: 'Provider profile deleted successfully'
    });
  });
}

module.exports = ProviderController;