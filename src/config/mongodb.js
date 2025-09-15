const mongoose = require('mongoose');
const GridFSBucket = require('mongodb').GridFSBucket;
const logger = require('./logger');

let gridFSBucket;

// MongoDB connection
async function connectMongoDB() {
  try {
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_system';
    
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });

    logger.info('MongoDB connected successfully');

    // Initialize GridFS bucket for file uploads
    gridFSBucket = new GridFSBucket(mongoose.connection.db, {
      bucketName: process.env.MONGODB_GRIDFS_BUCKET || 'uploads'
    });

    logger.info('GridFS bucket initialized');

    return mongoose.connection;
  } catch (error) {
    logger.error('MongoDB connection failed:', error);
    throw error;
  }
}

// Get GridFS bucket
function getGridFSBucket() {
  if (!gridFSBucket) {
    throw new Error('GridFS bucket not initialized. Make sure MongoDB is connected.');
  }
  return gridFSBucket;
}

// Connection event handlers
mongoose.connection.on('connected', () => {
  logger.info('Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (error) => {
  logger.error('Mongoose connection error:', error);
});

mongoose.connection.on('disconnected', () => {
  logger.warn('Mongoose disconnected from MongoDB');
});

// Graceful shutdown
process.on('SIGINT', async () => {
  try {
    await mongoose.connection.close();
    logger.info('MongoDB connection closed through app termination');
    process.exit(0);
  } catch (error) {
    logger.error('Error closing MongoDB connection:', error);
    process.exit(1);
  }
});

process.on('SIGTERM', async () => {
  try {
    await mongoose.connection.close();
    logger.info('MongoDB connection closed through app termination');
    process.exit(0);
  } catch (error) {
    logger.error('Error closing MongoDB connection:', error);
    process.exit(1);
  }
});

module.exports = {
  connectMongoDB,
  getGridFSBucket,
  mongoose
};