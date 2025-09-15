const { query } = require('../config/database');
const logger = require('../config/logger');

// Database setup script
async function setupDatabase() {
  try {
    logger.info('Setting up database tables...');
    
    // Check if tables exist
    const result = await query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    
    const existingTables = result.rows.map(row => row.table_name);
    
    if (existingTables.length === 0) {
      logger.info('No tables found. Please run the schema.sql file first.');
      logger.info('Command: psql -h localhost -U auth_user -d auth_system -f database/schema.sql');
      process.exit(1);
    }
    
    logger.info('Database tables found:', existingTables);
    
    // Verify essential tables exist
    const requiredTables = [
      'users',
      'provider_profiles',
      'user_sessions',
      'password_reset_tokens',
      'email_verification_tokens',
      'audit_logs',
      'file_uploads',
      'gdpr_requests'
    ];
    
    const missingTables = requiredTables.filter(table => !existingTables.includes(table));
    
    if (missingTables.length > 0) {
      logger.error('Missing required tables:', missingTables);
      logger.error('Please run the complete schema.sql file');
      process.exit(1);
    }
    
    logger.info('✅ All required tables are present');
    
    // Check if admin user exists
    const adminResult = await query(`
      SELECT id, email FROM users WHERE role = 'admin' LIMIT 1
    `);
    
    if (adminResult.rows.length === 0) {
      logger.warn('⚠️  No admin user found. You should create one manually.');
      logger.info('Example SQL to create admin user:');
      logger.info(`
        INSERT INTO users (email, password_hash, first_name, last_name, role, is_active, is_verified, gdpr_consent, gdpr_consent_date)
        VALUES (
          'admin@yourdomain.com',
          '$argon2id$v=19$m=65536,t=3,p=4$...',  -- Use proper Argon2id hash
          'System',
          'Administrator',
          'admin',
          true,
          true,
          true,
          NOW()
        );
      `);
    } else {
      logger.info('✅ Admin user found:', adminResult.rows[0].email);
    }
    
    logger.info('✅ Database setup validation completed');
    
  } catch (error) {
    logger.error('Database setup failed:', error);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  setupDatabase().then(() => {
    process.exit(0);
  });
}

module.exports = setupDatabase;