const logger = require('../config/logger');

// 404 Not Found handler
const notFoundHandler = (req, res, next) => {
  logger.warn('404 Not Found', {
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id
  });

  res.status(404).json({
    status: 'fail',
    message: `Route ${req.method} ${req.url} not found`,
    code: 'ROUTE_NOT_FOUND'
  });
};

module.exports = {
  notFoundHandler
};