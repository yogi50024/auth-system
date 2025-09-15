const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// Generate random string
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// Generate secure token
function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('base64url');
}

// Hash password with salt
function hashWithSalt(password, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(16).toString('hex');
  }
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

// Verify hashed password
function verifyHash(password, hash, salt) {
  const { hash: computedHash } = hashWithSalt(password, salt);
  return hash === computedHash;
}

// Encrypt text
function encrypt(text, secretKey = process.env.JWT_SECRET) {
  const algorithm = 'aes-256-gcm';
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipher(algorithm, secretKey, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

// Decrypt text
function decrypt(encryptedData, secretKey = process.env.JWT_SECRET) {
  const algorithm = 'aes-256-gcm';
  const decipher = crypto.createDecipher(algorithm, secretKey, Buffer.from(encryptedData.iv, 'hex'));
  
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// Generate JWT token with custom payload
function generateJWT(payload, secret = process.env.JWT_SECRET, options = {}) {
  const defaultOptions = {
    issuer: 'auth-system',
    audience: 'auth-system-users',
    expiresIn: '15m'
  };
  
  return jwt.sign(payload, secret, { ...defaultOptions, ...options });
}

// Verify JWT token
function verifyJWT(token, secret = process.env.JWT_SECRET, options = {}) {
  const defaultOptions = {
    issuer: 'auth-system',
    audience: 'auth-system-users'
  };
  
  return jwt.verify(token, secret, { ...defaultOptions, ...options });
}

// Create HMAC signature
function createSignature(data, secret = process.env.JWT_SECRET) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

// Verify HMAC signature
function verifySignature(data, signature, secret = process.env.JWT_SECRET) {
  const expectedSignature = createSignature(data, secret);
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  );
}

// Generate UUID
function generateUUID() {
  return uuidv4();
}

// Generate numeric code (for MFA, verification, etc.)
function generateNumericCode(length = 6) {
  let code = '';
  for (let i = 0; i < length; i++) {
    code += Math.floor(Math.random() * 10);
  }
  return code;
}

// Time-safe string comparison
function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// Hash data with SHA-256
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Generate API key
function generateAPIKey(prefix = 'ak') {
  const randomPart = crypto.randomBytes(32).toString('base64url');
  return `${prefix}_${randomPart}`;
}

// Mask sensitive data (for logging)
function maskSensitiveData(data, fields = ['password', 'token', 'secret', 'key']) {
  if (typeof data !== 'object' || data === null) {
    return data;
  }
  
  const masked = { ...data };
  
  for (const field of fields) {
    if (masked[field]) {
      masked[field] = '***MASKED***';
    }
  }
  
  return masked;
}

// Validate email format
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Validate password strength
function validatePasswordStrength(password) {
  const minLength = 8;
  const maxLength = 128;
  
  const criteria = {
    length: password.length >= minLength && password.length <= maxLength,
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    number: /\d/.test(password),
    special: /[@$!%*?&]/.test(password)
  };
  
  const score = Object.values(criteria).filter(Boolean).length;
  const isValid = score >= 4; // All criteria except maybe length
  
  return {
    isValid,
    score,
    criteria,
    strength: score <= 2 ? 'weak' : score <= 3 ? 'medium' : 'strong'
  };
}

// Sanitize filename for safe storage
function sanitizeFilename(filename) {
  return filename
    .replace(/[^a-zA-Z0-9.-]/g, '_')
    .replace(/_{2,}/g, '_')
    .toLowerCase();
}

// Generate file hash
function generateFileHash(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Format file size
function formatFileSize(bytes) {
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  if (bytes === 0) return '0 Bytes';
  
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
}

// Parse user agent
function parseUserAgent(userAgent) {
  if (!userAgent) return {};
  
  const browserMatch = userAgent.match(/(Chrome|Firefox|Safari|Edge|Opera)\/?([\d.]+)/);
  const osMatch = userAgent.match(/(Windows|Mac|Linux|iOS|Android)/);
  
  return {
    browser: browserMatch ? browserMatch[1] : 'Unknown',
    version: browserMatch ? browserMatch[2] : 'Unknown',
    os: osMatch ? osMatch[1] : 'Unknown',
    userAgent
  };
}

// Rate limiting key generator
function generateRateLimitKey(req, prefix = 'rate_limit') {
  return `${prefix}:${req.ip}:${req.user?.id || 'anonymous'}`;
}

// Sleep function
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Retry function with exponential backoff
async function retry(fn, options = {}) {
  const {
    maxAttempts = 3,
    baseDelay = 1000,
    maxDelay = 10000,
    backoffFactor = 2
  } = options;
  
  let attempt = 1;
  let delay = baseDelay;
  
  while (attempt <= maxAttempts) {
    try {
      return await fn();
    } catch (error) {
      if (attempt === maxAttempts) {
        throw error;
      }
      
      await sleep(Math.min(delay, maxDelay));
      delay *= backoffFactor;
      attempt++;
    }
  }
}

// Deep clone object
function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

// Remove undefined values from object
function removeUndefined(obj) {
  const cleaned = {};
  
  for (const [key, value] of Object.entries(obj)) {
    if (value !== undefined) {
      cleaned[key] = value;
    }
  }
  
  return cleaned;
}

module.exports = {
  generateRandomString,
  generateSecureToken,
  hashWithSalt,
  verifyHash,
  encrypt,
  decrypt,
  generateJWT,
  verifyJWT,
  createSignature,
  verifySignature,
  generateUUID,
  generateNumericCode,
  timingSafeEqual,
  sha256,
  generateAPIKey,
  maskSensitiveData,
  isValidEmail,
  validatePasswordStrength,
  sanitizeFilename,
  generateFileHash,
  formatFileSize,
  parseUserAgent,
  generateRateLimitKey,
  sleep,
  retry,
  deepClone,
  removeUndefined
};