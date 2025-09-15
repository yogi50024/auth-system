const express = require('express');
const { query } = require('../config/database');
const { redisClient } = require('../config/redis');
const { mongoose } = require('../config/mongodb');
const logger = require('../config/logger');

const router = express.Router();

// Basic health check
router.get('/', async (req, res) => {
  const healthCheck = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    service: 'Auth System',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  };

  res.status(200).json(healthCheck);
});

// Detailed health check with database connections
router.get('/detailed', async (req, res) => {
  const healthCheck = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    service: 'Auth System',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    checks: {
      postgresql: { status: 'unknown' },
      mongodb: { status: 'unknown' },
      redis: { status: 'unknown' }
    }
  };

  let overallStatus = 'healthy';

  // Check PostgreSQL
  try {
    await query('SELECT 1');
    healthCheck.checks.postgresql = {
      status: 'healthy',
      message: 'Connected'
    };
  } catch (error) {
    healthCheck.checks.postgresql = {
      status: 'unhealthy',
      message: error.message
    };
    overallStatus = 'unhealthy';
    logger.error('PostgreSQL health check failed:', error);
  }

  // Check MongoDB
  try {
    if (mongoose.connection.readyState === 1) {
      healthCheck.checks.mongodb = {
        status: 'healthy',
        message: 'Connected'
      };
    } else {
      throw new Error('Not connected');
    }
  } catch (error) {
    healthCheck.checks.mongodb = {
      status: 'unhealthy',
      message: error.message
    };
    overallStatus = 'unhealthy';
    logger.error('MongoDB health check failed:', error);
  }

  // Check Redis
  try {
    if (redisClient.isOpen) {
      await redisClient.ping();
      healthCheck.checks.redis = {
        status: 'healthy',
        message: 'Connected'
      };
    } else {
      throw new Error('Not connected');
    }
  } catch (error) {
    healthCheck.checks.redis = {
      status: 'unhealthy',
      message: error.message
    };
    overallStatus = 'unhealthy';
    logger.error('Redis health check failed:', error);
  }

  healthCheck.status = overallStatus;
  
  const statusCode = overallStatus === 'healthy' ? 200 : 503;
  res.status(statusCode).json(healthCheck);
});

// Readiness probe (for Kubernetes)
router.get('/ready', async (req, res) => {
  try {
    // Check if all critical services are available
    await query('SELECT 1');
    await redisClient.ping();
    
    if (mongoose.connection.readyState !== 1) {
      throw new Error('MongoDB not ready');
    }

    res.status(200).json({
      status: 'ready',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Readiness check failed:', error);
    res.status(503).json({
      status: 'not ready',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

// Liveness probe (for Kubernetes)
router.get('/live', (req, res) => {
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// System metrics
router.get('/metrics', (req, res) => {
  const used = process.memoryUsage();
  const metrics = {
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: {
      rss: Math.round(used.rss / 1024 / 1024 * 100) / 100,
      heapTotal: Math.round(used.heapTotal / 1024 / 1024 * 100) / 100,
      heapUsed: Math.round(used.heapUsed / 1024 / 1024 * 100) / 100,
      external: Math.round(used.external / 1024 / 1024 * 100) / 100
    },
    cpu: process.cpuUsage(),
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch
  };

  res.status(200).json(metrics);
});

module.exports = router;