const { query, transaction } = require('../config/database');
const { v4: uuidv4 } = require('uuid');
const logger = require('../config/logger');
const User = require('./User');

class Provider {
  constructor(data) {
    Object.assign(this, data);
  }

  // Create a new provider profile
  static async create(userId, providerData) {
    const {
      businessName,
      businessType,
      licenseNumber,
      taxId,
      businessAddress,
      website,
      description
    } = providerData;

    return await transaction(async (client) => {
      // Verify user exists and is not already a provider
      const userResult = await client.query(`
        SELECT id, role FROM users WHERE id = $1 AND is_active = true
      `, [userId]);

      if (userResult.rows.length === 0) {
        throw new Error('User not found');
      }

      // Check if provider profile already exists
      const existingProvider = await client.query(`
        SELECT id FROM provider_profiles WHERE user_id = $1
      `, [userId]);

      if (existingProvider.rows.length > 0) {
        throw new Error('Provider profile already exists for this user');
      }

      // Create provider profile
      const result = await client.query(`
        INSERT INTO provider_profiles (
          user_id, business_name, business_type, license_number, tax_id,
          business_address, website, description, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, user_id, business_name, business_type, license_number,
                  tax_id, status, business_address, website, description,
                  created_at, updated_at
      `, [
        userId,
        businessName,
        businessType,
        licenseNumber,
        taxId,
        JSON.stringify(businessAddress),
        website,
        description,
        'pending'
      ]);

      // Update user role to provider
      await client.query(`
        UPDATE users SET role = 'provider', updated_at = NOW()
        WHERE id = $1
      `, [userId]);

      // Log provider registration
      await User.logAuditEvent(
        client, 
        userId, 
        'provider_registered', 
        'provider_profile', 
        result.rows[0].id
      );

      const provider = new Provider(result.rows[0]);
      provider.business_address = JSON.parse(provider.business_address);
      return provider;
    });
  }

  // Find provider by ID
  static async findById(id) {
    const result = await query(`
      SELECT pp.*, u.email, u.first_name, u.last_name, u.phone, u.is_active, u.is_verified
      FROM provider_profiles pp
      JOIN users u ON pp.user_id = u.id
      WHERE pp.id = $1
    `, [id]);

    if (result.rows.length === 0) {
      return null;
    }

    const provider = new Provider(result.rows[0]);
    provider.business_address = JSON.parse(provider.business_address);
    return provider;
  }

  // Find provider by user ID
  static async findByUserId(userId) {
    const result = await query(`
      SELECT pp.*, u.email, u.first_name, u.last_name, u.phone, u.is_active, u.is_verified
      FROM provider_profiles pp
      JOIN users u ON pp.user_id = u.id
      WHERE pp.user_id = $1
    `, [userId]);

    if (result.rows.length === 0) {
      return null;
    }

    const provider = new Provider(result.rows[0]);
    provider.business_address = JSON.parse(provider.business_address);
    return provider;
  }

  // Update provider profile
  async update(updateData) {
    const allowedFields = [
      'business_name', 'business_type', 'license_number', 'tax_id',
      'business_address', 'website', 'description', 'status',
      'verification_documents', 'verified_at', 'verified_by', 'rejection_reason'
    ];

    const fields = [];
    const values = [];
    let paramCount = 1;

    Object.keys(updateData).forEach(key => {
      if (allowedFields.includes(key) && updateData[key] !== undefined) {
        let value = updateData[key];
        
        // Convert objects to JSON strings for storage
        if (key === 'business_address' || key === 'verification_documents') {
          value = JSON.stringify(value);
        }
        
        fields.push(`${key} = $${paramCount}`);
        values.push(value);
        paramCount++;
      }
    });

    if (fields.length === 0) {
      throw new Error('No valid fields to update');
    }

    values.push(this.id);

    const result = await query(`
      UPDATE provider_profiles SET ${fields.join(', ')}, updated_at = NOW()
      WHERE id = $${paramCount}
      RETURNING id, user_id, business_name, business_type, license_number,
                tax_id, status, business_address, website, description,
                verification_documents, verified_at, verified_by,
                rejection_reason, created_at, updated_at
    `, values);

    if (result.rows.length > 0) {
      Object.assign(this, result.rows[0]);
      if (this.business_address) {
        this.business_address = JSON.parse(this.business_address);
      }
      if (this.verification_documents) {
        this.verification_documents = JSON.parse(this.verification_documents);
      }
    }

    // Log update
    await User.logAuditEvent(null, this.user_id, 'provider_updated', 'provider_profile', this.id);

    return this;
  }

  // Verify provider
  async verify(verifiedBy, verificationDocuments = null) {
    return await transaction(async (client) => {
      const updateData = {
        status: 'active',
        verified_at: new Date(),
        verified_by: verifiedBy,
        rejection_reason: null
      };

      if (verificationDocuments) {
        updateData.verification_documents = verificationDocuments;
      }

      await this.update(updateData);

      // Log verification
      await User.logAuditEvent(
        client,
        verifiedBy,
        'provider_verified',
        'provider_profile',
        this.id,
        { verified_user_id: this.user_id }
      );

      return this;
    });
  }

  // Reject provider
  async reject(rejectedBy, reason) {
    return await transaction(async (client) => {
      await this.update({
        status: 'rejected',
        rejection_reason: reason,
        verified_at: null,
        verified_by: null
      });

      // Log rejection
      await User.logAuditEvent(
        client,
        rejectedBy,
        'provider_rejected',
        'provider_profile',
        this.id,
        { 
          rejected_user_id: this.user_id,
          reason: reason
        }
      );

      return this;
    });
  }

  // Suspend provider
  async suspend(suspendedBy, reason) {
    return await transaction(async (client) => {
      await this.update({
        status: 'suspended',
        rejection_reason: reason
      });

      // Log suspension
      await User.logAuditEvent(
        client,
        suspendedBy,
        'provider_suspended',
        'provider_profile',
        this.id,
        { 
          suspended_user_id: this.user_id,
          reason: reason
        }
      );

      return this;
    });
  }

  // Reactivate provider
  async reactivate(reactivatedBy) {
    return await transaction(async (client) => {
      await this.update({
        status: 'active',
        rejection_reason: null
      });

      // Log reactivation
      await User.logAuditEvent(
        client,
        reactivatedBy,
        'provider_reactivated',
        'provider_profile',
        this.id,
        { reactivated_user_id: this.user_id }
      );

      return this;
    });
  }

  // Get provider list with pagination and filters
  static async getList(options = {}) {
    const {
      page = 1,
      limit = 20,
      sort = 'created_at',
      order = 'desc',
      status,
      businessType,
      search
    } = options;

    const offset = (page - 1) * limit;
    const conditions = [];
    const values = [];
    let paramCount = 1;

    if (status) {
      conditions.push(`pp.status = $${paramCount}`);
      values.push(status);
      paramCount++;
    }

    if (businessType) {
      conditions.push(`pp.business_type = $${paramCount}`);
      values.push(businessType);
      paramCount++;
    }

    if (search) {
      conditions.push(`(
        pp.business_name ILIKE $${paramCount} OR 
        u.first_name ILIKE $${paramCount} OR 
        u.last_name ILIKE $${paramCount} OR
        u.email ILIKE $${paramCount}
      )`);
      values.push(`%${search}%`);
      paramCount++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    
    values.push(limit, offset);

    const result = await query(`
      SELECT 
        pp.id, pp.user_id, pp.business_name, pp.business_type, pp.license_number,
        pp.status, pp.business_address, pp.website, pp.verified_at, pp.created_at, pp.updated_at,
        u.email, u.first_name, u.last_name, u.phone, u.is_active, u.is_verified
      FROM provider_profiles pp
      JOIN users u ON pp.user_id = u.id
      ${whereClause}
      ORDER BY pp.${sort} ${order.toUpperCase()}
      LIMIT $${paramCount} OFFSET $${paramCount + 1}
    `, values);

    // Get total count
    const countResult = await query(`
      SELECT COUNT(*) as total 
      FROM provider_profiles pp
      JOIN users u ON pp.user_id = u.id
      ${whereClause}
    `, values.slice(0, -2));

    const providers = result.rows.map(row => {
      const provider = new Provider(row);
      provider.business_address = JSON.parse(provider.business_address);
      return provider;
    });

    return {
      providers,
      total: parseInt(countResult.rows[0].total),
      page,
      limit,
      totalPages: Math.ceil(countResult.rows[0].total / limit)
    };
  }

  // Get provider statistics
  static async getStatistics() {
    const result = await query(`
      SELECT 
        COUNT(*) as total,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
        COUNT(CASE WHEN status = 'suspended' THEN 1 END) as suspended,
        COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected,
        COUNT(CASE WHEN business_type = 'individual' THEN 1 END) as individual,
        COUNT(CASE WHEN business_type = 'corporation' THEN 1 END) as corporation,
        COUNT(CASE WHEN business_type = 'llc' THEN 1 END) as llc,
        COUNT(CASE WHEN business_type = 'partnership' THEN 1 END) as partnership,
        COUNT(CASE WHEN business_type = 'nonprofit' THEN 1 END) as nonprofit
      FROM provider_profiles
    `);

    return result.rows[0];
  }

  // Get pending verifications count
  static async getPendingVerificationsCount() {
    const result = await query(`
      SELECT COUNT(*) as pending_count
      FROM provider_profiles
      WHERE status = 'pending'
    `);

    return parseInt(result.rows[0].pending_count);
  }

  // Upload verification document
  async addVerificationDocument(fileData) {
    const documents = this.verification_documents || [];
    
    documents.push({
      id: uuidv4(),
      filename: fileData.filename,
      originalName: fileData.originalName,
      mimeType: fileData.mimeType,
      size: fileData.size,
      uploadedAt: new Date(),
      type: fileData.type || 'general'
    });

    await this.update({
      verification_documents: documents
    });

    return documents[documents.length - 1];
  }

  // Remove verification document
  async removeVerificationDocument(documentId) {
    const documents = this.verification_documents || [];
    const updatedDocuments = documents.filter(doc => doc.id !== documentId);

    await this.update({
      verification_documents: updatedDocuments
    });

    return updatedDocuments;
  }

  // Delete provider profile
  async delete() {
    return await transaction(async (client) => {
      // Update user role back to 'user'
      await client.query(`
        UPDATE users SET role = 'user', updated_at = NOW()
        WHERE id = $1
      `, [this.user_id]);

      // Delete provider profile
      await client.query(`
        DELETE FROM provider_profiles WHERE id = $1
      `, [this.id]);

      // Log deletion
      await User.logAuditEvent(
        client,
        this.user_id,
        'provider_deleted',
        'provider_profile',
        this.id
      );

      return true;
    });
  }

  // Convert to JSON
  toJSON() {
    const data = { ...this };
    
    // Ensure business_address is an object
    if (typeof data.business_address === 'string') {
      try {
        data.business_address = JSON.parse(data.business_address);
      } catch (error) {
        logger.error('Error parsing business_address:', error);
        data.business_address = {};
      }
    }

    // Ensure verification_documents is an array
    if (typeof data.verification_documents === 'string') {
      try {
        data.verification_documents = JSON.parse(data.verification_documents);
      } catch (error) {
        logger.error('Error parsing verification_documents:', error);
        data.verification_documents = [];
      }
    }

    return data;
  }
}

module.exports = Provider;