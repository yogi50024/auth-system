const { validationResult, body, param, query } = require('express-validator');
const { AppError } = require('./errorHandler');

// Handle validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => ({
      field: error.path,
      message: error.msg,
      value: error.value
    }));

    return next(new AppError('Validation failed', 400, 'VALIDATION_ERROR'));
  }

  next();
};

// User registration validation
const validateUserRegistration = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  
  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),
  
  body('firstName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('First name can only contain letters, spaces, hyphens, and apostrophes'),
  
  body('lastName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Last name can only contain letters, spaces, hyphens, and apostrophes'),
  
  body('role')
    .optional()
    .isIn(['user', 'provider', 'admin'])
    .withMessage('Role must be either user, provider, or admin'),
  
  body('phone')
    .optional()
    .isMobilePhone()
    .withMessage('Please provide a valid phone number'),
  
  body('dateOfBirth')
    .optional()
    .isISO8601()
    .withMessage('Please provide a valid date of birth'),
  
  body('gdprConsent')
    .isBoolean()
    .custom(value => value === true)
    .withMessage('GDPR consent is required'),
  
  handleValidationErrors
];

// User login validation
const validateUserLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  
  body('mfaCode')
    .optional()
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('MFA code must be 6 digits'),
  
  handleValidationErrors
];

// Provider registration validation
const validateProviderRegistration = [
  ...validateUserRegistration.slice(0, -1), // Reuse user validation except handleValidationErrors
  
  body('businessName')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Business name must be between 1 and 100 characters'),
  
  body('businessType')
    .isIn(['individual', 'partnership', 'corporation', 'llc', 'nonprofit'])
    .withMessage('Please select a valid business type'),
  
  body('licenseNumber')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('License number must be between 1 and 50 characters'),
  
  body('businessAddress.street')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Street address is required'),
  
  body('businessAddress.city')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('City is required'),
  
  body('businessAddress.state')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('State is required'),
  
  body('businessAddress.zipCode')
    .trim()
    .matches(/^\d{5}(-\d{4})?$/)
    .withMessage('Please provide a valid ZIP code'),
  
  body('businessAddress.country')
    .trim()
    .isLength({ min: 2, max: 2 })
    .withMessage('Country code must be 2 characters'),
  
  handleValidationErrors
];

// Password reset request validation
const validatePasswordResetRequest = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  
  handleValidationErrors
];

// Password reset validation
const validatePasswordReset = [
  body('token')
    .notEmpty()
    .withMessage('Reset token is required'),
  
  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),
  
  handleValidationErrors
];

// Change password validation
const validateChangePassword = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  
  body('newPassword')
    .isLength({ min: 8, max: 128 })
    .withMessage('New password must be between 8 and 128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('New password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),
  
  handleValidationErrors
];

// MFA setup validation
const validateMFASetup = [
  body('secret')
    .notEmpty()
    .withMessage('MFA secret is required'),
  
  body('token')
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('MFA token must be 6 digits'),
  
  handleValidationErrors
];

// MFA verification validation
const validateMFAVerification = [
  body('token')
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('MFA token must be 6 digits'),
  
  handleValidationErrors
];

// Update profile validation
const validateProfileUpdate = [
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('First name can only contain letters, spaces, hyphens, and apostrophes'),
  
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Last name can only contain letters, spaces, hyphens, and apostrophes'),
  
  body('phone')
    .optional()
    .isMobilePhone()
    .withMessage('Please provide a valid phone number'),
  
  body('dateOfBirth')
    .optional()
    .isISO8601()
    .withMessage('Please provide a valid date of birth'),
  
  handleValidationErrors
];

// Email verification validation
const validateEmailVerification = [
  body('token')
    .notEmpty()
    .withMessage('Verification token is required'),
  
  handleValidationErrors
];

// Refresh token validation
const validateRefreshToken = [
  body('refresh_token')
    .notEmpty()
    .withMessage('Refresh token is required'),
  
  handleValidationErrors
];

// UUID parameter validation
const validateUUIDParam = (paramName = 'id') => [
  param(paramName)
    .isUUID()
    .withMessage(`${paramName} must be a valid UUID`),
  
  handleValidationErrors
];

// Pagination validation
const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Page must be a number between 1 and 1000'),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be a number between 1 and 100'),
  
  query('sort')
    .optional()
    .isIn(['created_at', 'updated_at', 'email', 'first_name', 'last_name'])
    .withMessage('Sort field must be one of: created_at, updated_at, email, first_name, last_name'),
  
  query('order')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Order must be either asc or desc'),
  
  handleValidationErrors
];

// File upload validation
const validateFileUpload = [
  body('fileType')
    .optional()
    .isIn(['license', 'certificate', 'identification'])
    .withMessage('File type must be license, certificate, or identification'),
  
  handleValidationErrors
];

module.exports = {
  handleValidationErrors,
  validateUserRegistration,
  validateUserLogin,
  validateProviderRegistration,
  validatePasswordResetRequest,
  validatePasswordReset,
  validateChangePassword,
  validateMFASetup,
  validateMFAVerification,
  validateProfileUpdate,
  validateEmailVerification,
  validateRefreshToken,
  validateUUIDParam,
  validatePagination,
  validateFileUpload
};