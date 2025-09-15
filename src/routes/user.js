const express = require('express');
const UserController = require('../controllers/userController');
const {
  authenticateJWT,
  authorize,
  authorizeOwnerOrAdmin,
  requireVerification
} = require('../middleware/auth');
const {
  validateProfileUpdate,
  validatePagination,
  validateUUIDParam
} = require('../middleware/validation');

const router = express.Router();

// All routes require authentication
router.use(authenticateJWT);

// Get current user profile
router.get('/profile', UserController.getUserById);

// Update current user profile
router.put('/profile',
  requireVerification,
  validateProfileUpdate,
  (req, res, next) => {
    req.params.id = req.user.id;
    next();
  },
  UserController.updateProfile
);

// Delete current user account
router.delete('/account',
  (req, res, next) => {
    req.params.id = req.user.id;
    next();
  },
  UserController.deleteAccount
);

// Get user activity logs
router.get('/activity',
  validatePagination,
  (req, res, next) => {
    req.params.id = req.user.id;
    next();
  },
  UserController.getUserActivity
);

// Admin-only routes
router.use(authorize('admin'));

// Get all users with pagination and filters
router.get('/',
  validatePagination,
  UserController.getUsers
);

// Search users
router.get('/search',
  validatePagination,
  UserController.searchUsers
);

// Get user statistics
router.get('/statistics',
  UserController.getUserStatistics
);

// Get specific user by ID
router.get('/:id',
  validateUUIDParam('id'),
  UserController.getUserById
);

// Update user (admin)
router.put('/:id',
  validateUUIDParam('id'),
  validateProfileUpdate,
  UserController.updateUser
);

// Deactivate user
router.patch('/:id/deactivate',
  validateUUIDParam('id'),
  UserController.deactivateUser
);

// Reactivate user
router.patch('/:id/reactivate',
  validateUUIDParam('id'),
  UserController.reactivateUser
);

// Get user activity logs
router.get('/:id/activity',
  validateUUIDParam('id'),
  validatePagination,
  UserController.getUserActivity
);

// Delete user account (admin)
router.delete('/:id',
  validateUUIDParam('id'),
  UserController.deleteAccount
);

module.exports = router;