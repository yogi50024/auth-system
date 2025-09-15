-- PostgreSQL Database Schema for Auth System
-- Create database and user (run as postgres superuser)

-- CREATE DATABASE auth_system;
-- CREATE USER auth_user WITH ENCRYPTED PASSWORD 'your_postgres_password';
-- GRANT ALL PRIVILEGES ON DATABASE auth_system TO auth_user;

-- Connect to auth_system database and run the following:

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Create custom types
CREATE TYPE user_role AS ENUM ('user', 'provider', 'admin');
CREATE TYPE provider_status AS ENUM ('pending', 'active', 'suspended', 'rejected');
CREATE TYPE business_type AS ENUM ('individual', 'partnership', 'corporation', 'llc', 'nonprofit');

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email CITEXT UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    role user_role NOT NULL DEFAULT 'user',
    phone VARCHAR(20),
    date_of_birth DATE,
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_verified BOOLEAN NOT NULL DEFAULT false,
    email_verification_token VARCHAR(255),
    email_verification_expires TIMESTAMP WITH TIME ZONE,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP WITH TIME ZONE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    mfa_secret VARCHAR(255),
    mfa_backup_codes JSON,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    last_login TIMESTAMP WITH TIME ZONE,
    gdpr_consent BOOLEAN NOT NULL DEFAULT false,
    gdpr_consent_date TIMESTAMP WITH TIME ZONE,
    data_retention_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Provider profiles table
CREATE TABLE provider_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    business_name VARCHAR(100) NOT NULL,
    business_type business_type NOT NULL,
    license_number VARCHAR(50),
    tax_id VARCHAR(20),
    status provider_status NOT NULL DEFAULT 'pending',
    verification_documents JSON,
    business_address JSON NOT NULL,
    website VARCHAR(255),
    description TEXT,
    verified_at TIMESTAMP WITH TIME ZONE,
    verified_by UUID REFERENCES users(id),
    rejection_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(user_id)
);

-- User sessions table
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Password reset tokens table
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Email verification tokens table
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Audit log table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    details JSON,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- File uploads metadata table
CREATE TABLE file_uploads (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_size INTEGER NOT NULL,
    file_path VARCHAR(500),
    mongodb_file_id VARCHAR(255),
    file_type VARCHAR(50),
    is_verified BOOLEAN DEFAULT false,
    verified_at TIMESTAMP WITH TIME ZONE,
    verified_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- GDPR data requests table
CREATE TABLE gdpr_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    request_type VARCHAR(20) NOT NULL CHECK (request_type IN ('export', 'delete')),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    requested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    export_file_path VARCHAR(500),
    notes TEXT
);

-- User permissions table (for granular RBAC)
CREATE TABLE user_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, permission, resource)
);

-- Blacklisted tokens table (backup for Redis)
CREATE TABLE blacklisted_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    jti VARCHAR(255) NOT NULL UNIQUE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    blacklisted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_active ON users(is_active);
CREATE INDEX idx_users_is_verified ON users(is_verified);
CREATE INDEX idx_users_created_at ON users(created_at);

CREATE INDEX idx_provider_profiles_user_id ON provider_profiles(user_id);
CREATE INDEX idx_provider_profiles_status ON provider_profiles(status);
CREATE INDEX idx_provider_profiles_business_name ON provider_profiles(business_name);

CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_session_token ON user_sessions(session_token);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX idx_user_sessions_is_active ON user_sessions(is_active);

CREATE INDEX idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

CREATE INDEX idx_email_verification_tokens_token ON email_verification_tokens(token);
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
CREATE INDEX idx_email_verification_tokens_expires_at ON email_verification_tokens(expires_at);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

CREATE INDEX idx_file_uploads_user_id ON file_uploads(user_id);
CREATE INDEX idx_file_uploads_file_type ON file_uploads(file_type);
CREATE INDEX idx_file_uploads_is_verified ON file_uploads(is_verified);

CREATE INDEX idx_gdpr_requests_user_id ON gdpr_requests(user_id);
CREATE INDEX idx_gdpr_requests_status ON gdpr_requests(status);
CREATE INDEX idx_gdpr_requests_requested_at ON gdpr_requests(requested_at);

CREATE INDEX idx_user_permissions_user_id ON user_permissions(user_id);
CREATE INDEX idx_user_permissions_permission ON user_permissions(permission);

CREATE INDEX idx_blacklisted_tokens_jti ON blacklisted_tokens(jti);
CREATE INDEX idx_blacklisted_tokens_expires_at ON blacklisted_tokens(expires_at);

-- Create triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_provider_profiles_updated_at BEFORE UPDATE ON provider_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_sessions_updated_at BEFORE UPDATE ON user_sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_file_uploads_updated_at BEFORE UPDATE ON file_uploads
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create views for common queries
CREATE VIEW active_users AS
SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.last_login, u.created_at
FROM users u
WHERE u.is_active = true AND u.is_verified = true;

CREATE VIEW provider_summary AS
SELECT 
    u.id,
    u.email,
    u.first_name,
    u.last_name,
    pp.business_name,
    pp.business_type,
    pp.status,
    pp.verified_at,
    pp.created_at
FROM users u
JOIN provider_profiles pp ON u.id = pp.user_id
WHERE u.role = 'provider';

-- Create function to clean up expired tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    DELETE FROM password_reset_tokens WHERE expires_at < NOW();
    DELETE FROM email_verification_tokens WHERE expires_at < NOW();
    DELETE FROM user_sessions WHERE expires_at < NOW();
    DELETE FROM blacklisted_tokens WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Create function to get user permissions
CREATE OR REPLACE FUNCTION get_user_permissions(user_uuid UUID)
RETURNS TABLE(permission VARCHAR, resource VARCHAR) AS $$
BEGIN
    RETURN QUERY
    SELECT up.permission, up.resource
    FROM user_permissions up
    WHERE up.user_id = user_uuid
    AND (up.expires_at IS NULL OR up.expires_at > NOW());
END;
$$ LANGUAGE plpgsql;

-- Insert default admin user (change password in production!)
INSERT INTO users (
    email, 
    password_hash, 
    first_name, 
    last_name, 
    role, 
    is_active, 
    is_verified,
    gdpr_consent,
    gdpr_consent_date
) VALUES (
    'admin@example.com',
    '$argon2id$v=19$m=65536,t=3,p=4$YourSecretSaltHere$YourHashedPasswordHere', -- Change this!
    'System',
    'Administrator',
    'admin',
    true,
    true,
    true,
    NOW()
) ON CONFLICT (email) DO NOTHING;

-- Export download tokens table (for GDPR data export downloads)
CREATE TABLE export_download_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id UUID NOT NULL REFERENCES gdpr_requests(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for export download tokens
CREATE INDEX idx_export_download_tokens_token ON export_download_tokens(token);
CREATE INDEX idx_export_download_tokens_expires_at ON export_download_tokens(expires_at);

-- Grant permissions to auth_user
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO auth_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO auth_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO auth_user;