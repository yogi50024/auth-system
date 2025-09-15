const express = require('express');
const GDPRController = require('../controllers/gdprController');
const {
  authenticateJWT,
  authorize,
  requireVerification
} = require('../middleware/auth');
const {
  gdprExportRateLimit
} = require('../middleware/rateLimiter');
const {
  validatePagination,
  validateUUIDParam
} = require('../middleware/validation');
const { body } = require('express-validator');

const router = express.Router();

// All routes require authentication
router.use(authenticateJWT);
router.use(requireVerification);

// Data export requests
router.post('/export',
  gdprExportRateLimit,
  GDPRController.requestDataExport
);

router.get('/download',
  GDPRController.downloadExport
);

// Account deletion requests
router.post('/delete-account',
  [
    body('confirmPassword')
      .notEmpty()
      .withMessage('Password confirmation is required')
  ],
  GDPRController.requestAccountDeletion
);

router.delete('/delete-account',
  GDPRController.cancelAccountDeletion
);

// Get user's GDPR requests
router.get('/requests',
  GDPRController.getGDPRRequests
);

// Get GDPR compliance status
router.get('/compliance-status',
  GDPRController.getComplianceStatus
);

// Update GDPR consent
router.put('/consent',
  [
    body('consent')
      .isBoolean()
      .withMessage('Consent must be a boolean value')
  ],
  GDPRController.updateGDPRConsent
);

// Admin-only routes
router.use(authorize('admin'));

// Get all GDPR requests
router.get('/admin/requests',
  validatePagination,
  GDPRController.getAllGDPRRequests
);

// Process account deletion
router.post('/admin/process-deletion/:requestId',
  validateUUIDParam('requestId'),
  GDPRController.processAccountDeletion
);

module.exports = router;