const { Pool } = require('pg');
const logger = require('./logger');

// PostgreSQL connection pool
const pool = new Pool({
  host: process.env.POSTGRES_HOST || 'localhost',
  port: parseInt(process.env.POSTGRES_PORT) || 5432,
  user: process.env.POSTGRES_USER || 'auth_user',
  password: process.env.POSTGRES_PASSWORD,
  database: process.env.POSTGRES_DATABASE || 'auth_system',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test connection
async function connectPostgres() {
  try {
    const client = await pool.connect();
    logger.info('PostgreSQL connected successfully');
    client.release();
    return true;
  } catch (error) {
    logger.error('PostgreSQL connection failed:', error);
    throw error;
  }
}

// Execute query with error handling
async function query(text, params) {
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    logger.debug('Query executed', { text, duration, rows: result.rowCount });
    return result;
  } catch (error) {
    logger.error('Database query error:', { text, error: error.message });
    throw error;
  }
}

// Get a client from the pool for transactions
async function getClient() {
  try {
    const client = await pool.connect();
    return client;
  } catch (error) {
    logger.error('Failed to get database client:', error);
    throw error;
  }
}

// Execute transaction
async function transaction(callback) {
  const client = await getClient();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error('Transaction failed:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Graceful shutdown
process.on('SIGINT', () => {
  logger.info('Closing PostgreSQL pool...');
  pool.end();
});

process.on('SIGTERM', () => {
  logger.info('Closing PostgreSQL pool...');
  pool.end();
});

module.exports = {
  pool,
  query,
  getClient,
  transaction,
  connectPostgres
};