const express = require('express');
const ProviderController = require('../controllers/providerController');
const fileService = require('../services/fileService');
const {
  authenticateJWT,
  authorize,
  requireVerification
} = require('../middleware/auth');
const {
  fileUploadRateLimit
} = require('../middleware/rateLimiter');
const {
  validateProviderRegistration,
  validatePagination,
  validateUUIDParam,
  validateFileUpload
} = require('../middleware/validation');

const router = express.Router();

// All routes require authentication
router.use(authenticateJWT);

// Provider registration and profile management
router.post('/register',
  requireVerification,
  validateProviderRegistration,
  ProviderController.registerProvider
);

router.get('/profile',
  ProviderController.getProviderProfile
);

router.put('/profile',
  requireVerification,
  validateProviderRegistration,
  ProviderController.updateProviderProfile
);

router.delete('/profile',
  ProviderController.deleteProviderProfile
);

// Document management
router.post('/documents',
  fileUploadRateLimit,
  fileService.createMulterConfig().array('documents', 5),
  validateFileUpload,
  ProviderController.uploadDocuments
);

router.get('/documents',
  ProviderController.getProviderDocuments
);

router.get('/documents/:documentId',
  validateUUIDParam('documentId'),
  ProviderController.downloadDocument
);

router.delete('/documents/:documentId',
  validateUUIDParam('documentId'),
  ProviderController.deleteDocument
);

// Admin-only routes
router.use(authorize('admin'));

// Get all providers with pagination and filters
router.get('/',
  validatePagination,
  ProviderController.getProviders
);

// Search providers
router.get('/search',
  validatePagination,
  ProviderController.searchProviders
);

// Get provider statistics
router.get('/statistics',
  ProviderController.getProviderStatistics
);

// Get pending verifications count
router.get('/pending-verifications',
  ProviderController.getPendingVerifications
);

// Get specific provider by ID
router.get('/:id',
  validateUUIDParam('id'),
  ProviderController.getProviderById
);

// Provider verification actions
router.patch('/:id/verify',
  validateUUIDParam('id'),
  ProviderController.verifyProvider
);

router.patch('/:id/reject',
  validateUUIDParam('id'),
  ProviderController.rejectProvider
);

router.patch('/:id/suspend',
  validateUUIDParam('id'),
  ProviderController.suspendProvider
);

router.patch('/:id/reactivate',
  validateUUIDParam('id'),
  ProviderController.reactivateProvider
);

// Get provider documents (admin view)
router.get('/:providerId/documents',
  validateUUIDParam('providerId'),
  ProviderController.getProviderDocuments
);

module.exports = router;