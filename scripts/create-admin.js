const argon2 = require('argon2');
const { query } = require('../src/config/database');
const logger = require('../src/config/logger');

// Create admin user script
async function createAdminUser() {
  try {
    const email = process.argv[2] || 'admin@yourdomain.com';
    const password = process.argv[3] || 'AdminPassword123!';
    const firstName = process.argv[4] || 'System';
    const lastName = process.argv[5] || 'Administrator';
    
    logger.info('Creating admin user...');
    
    // Check if admin user already exists
    const existingUser = await query(`
      SELECT id, email FROM users WHERE email = $1
    `, [email]);
    
    if (existingUser.rows.length > 0) {
      logger.warn('User with this email already exists:', email);
      process.exit(1);
    }
    
    // Hash password with Argon2id
    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
      hashLength: 50
    });
    
    // Create admin user
    const result = await query(`
      INSERT INTO users (
        email, password_hash, first_name, last_name, role, 
        is_active, is_verified, gdpr_consent, gdpr_consent_date
      ) VALUES ($1, $2, $3, $4, 'admin', true, true, true, NOW())
      RETURNING id, email, first_name, last_name, role
    `, [email, passwordHash, firstName, lastName]);
    
    const user = result.rows[0];
    
    logger.info('✅ Admin user created successfully:');
    logger.info('  ID:', user.id);
    logger.info('  Email:', user.email);
    logger.info('  Name:', user.first_name, user.last_name);
    logger.info('  Role:', user.role);
    
    logger.warn('⚠️  Please change the password after first login!');
    
  } catch (error) {
    logger.error('Failed to create admin user:', error);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  createAdminUser().then(() => {
    process.exit(0);
  });
}

module.exports = createAdminUser;