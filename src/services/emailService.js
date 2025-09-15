const nodemailer = require('nodemailer');
const logger = require('../config/logger');

class EmailService {
  constructor() {
    this.transporter = null;
    this.initializeTransporter();
  }

  // Initialize email transporter
  initializeTransporter() {
    try {
      this.transporter = nodemailer.createTransporter({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        },
        tls: {
          rejectUnauthorized: false
        }
      });

      // Verify connection
      this.transporter.verify((error, success) => {
        if (error) {
          logger.error('Email transporter verification failed:', error);
        } else {
          logger.info('Email transporter ready');
        }
      });
    } catch (error) {
      logger.error('Failed to initialize email transporter:', error);
    }
  }

  // Send email
  async sendEmail(to, subject, html, text = null) {
    try {
      if (!this.transporter) {
        throw new Error('Email transporter not initialized');
      }

      const mailOptions = {
        from: process.env.EMAIL_FROM || process.env.SMTP_USER,
        to,
        subject,
        html,
        text: text || this.htmlToText(html)
      };

      const info = await this.transporter.sendMail(mailOptions);
      
      logger.info('Email sent successfully', {
        to,
        subject,
        messageId: info.messageId
      });

      return {
        success: true,
        messageId: info.messageId
      };
    } catch (error) {
      logger.error('Failed to send email:', {
        to,
        subject,
        error: error.message
      });
      throw error;
    }
  }

  // Send verification email
  async sendVerificationEmail(email, token) {
    const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3001'}/verify-email?token=${token}`;
    
    const subject = 'Verify Your Email Address';
    const html = this.getVerificationEmailTemplate(verificationUrl);

    return await this.sendEmail(email, subject, html);
  }

  // Send password reset email
  async sendPasswordResetEmail(email, token) {
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3001'}/reset-password?token=${token}`;
    
    const subject = 'Reset Your Password';
    const html = this.getPasswordResetEmailTemplate(resetUrl);

    return await this.sendEmail(email, subject, html);
  }

  // Send welcome email
  async sendWelcomeEmail(user) {
    const subject = 'Welcome to Auth System';
    const html = this.getWelcomeEmailTemplate(user);

    return await this.sendEmail(user.email, subject, html);
  }

  // Send provider verification email
  async sendProviderVerificationEmail(provider, status, reason = null) {
    let subject, html;

    switch (status) {
      case 'approved':
        subject = 'Provider Application Approved';
        html = this.getProviderApprovedEmailTemplate(provider);
        break;
      case 'rejected':
        subject = 'Provider Application Rejected';
        html = this.getProviderRejectedEmailTemplate(provider, reason);
        break;
      case 'suspended':
        subject = 'Provider Account Suspended';
        html = this.getProviderSuspendedEmailTemplate(provider, reason);
        break;
      default:
        throw new Error('Invalid provider verification status');
    }

    return await this.sendEmail(provider.email, subject, html);
  }

  // Send MFA setup email
  async sendMFASetupEmail(user) {
    const subject = 'Multi-Factor Authentication Enabled';
    const html = this.getMFASetupEmailTemplate(user);

    return await this.sendEmail(user.email, subject, html);
  }

  // Send security alert email
  async sendSecurityAlertEmail(user, alertType, details = {}) {
    const subject = `Security Alert: ${alertType}`;
    const html = this.getSecurityAlertEmailTemplate(user, alertType, details);

    return await this.sendEmail(user.email, subject, html);
  }

  // Send GDPR data export email
  async sendGDPRExportEmail(user, downloadUrl) {
    const subject = 'Your Data Export is Ready';
    const html = this.getGDPRExportEmailTemplate(user, downloadUrl);

    return await this.sendEmail(user.email, subject, html);
  }

  // Get verification email template
  getVerificationEmailTemplate(verificationUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Verify Your Email</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #007bff; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .button { display: inline-block; padding: 12px 24px; background: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Verify Your Email Address</h1>
          </div>
          <div class="content">
            <p>Thank you for registering with Auth System!</p>
            <p>To complete your registration, please verify your email address by clicking the button below:</p>
            <a href="${verificationUrl}" class="button">Verify Email Address</a>
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p><a href="${verificationUrl}">${verificationUrl}</a></p>
            <p>This verification link will expire in 24 hours.</p>
            <p>If you didn't create an account with us, please ignore this email.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth System. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Get password reset email template
  getPasswordResetEmailTemplate(resetUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Reset Your Password</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .button { display: inline-block; padding: 12px 24px; background: #dc3545; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Reset Your Password</h1>
          </div>
          <div class="content">
            <p>We received a request to reset your password for your Auth System account.</p>
            <p>Click the button below to reset your password:</p>
            <a href="${resetUrl}" class="button">Reset Password</a>
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p><a href="${resetUrl}">${resetUrl}</a></p>
            <p>This reset link will expire in 1 hour.</p>
            <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth System. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Get welcome email template
  getWelcomeEmailTemplate(user) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Welcome to Auth System</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #28a745; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to Auth System</h1>
          </div>
          <div class="content">
            <p>Hello ${user.first_name},</p>
            <p>Welcome to Auth System! Your account has been successfully verified and is ready to use.</p>
            <p>You can now log in and access all features of our platform.</p>
            <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
            <p>Thank you for choosing Auth System!</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth System. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Get provider approved email template
  getProviderApprovedEmailTemplate(provider) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Provider Application Approved</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #28a745; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Provider Application Approved</h1>
          </div>
          <div class="content">
            <p>Congratulations ${provider.first_name}!</p>
            <p>Your provider application for "${provider.business_name}" has been approved.</p>
            <p>You can now access all provider features and start offering your services through our platform.</p>
            <p>Thank you for joining Auth System as a provider!</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth System. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Get provider rejected email template
  getProviderRejectedEmailTemplate(provider, reason) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Provider Application Rejected</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Provider Application Update</h1>
          </div>
          <div class="content">
            <p>Dear ${provider.first_name},</p>
            <p>Thank you for your interest in becoming a provider with Auth System.</p>
            <p>After careful review, we are unable to approve your provider application at this time.</p>
            ${reason ? `<p><strong>Reason:</strong> ${reason}</p>` : ''}
            <p>You may reapply in the future after addressing any concerns.</p>
            <p>If you have questions about this decision, please contact our support team.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth System. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Get provider suspended email template
  getProviderSuspendedEmailTemplate(provider, reason) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Provider Account Suspended</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #ffc107; color: black; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Account Suspension Notice</h1>
          </div>
          <div class="content">
            <p>Dear ${provider.first_name},</p>
            <p>Your provider account for "${provider.business_name}" has been temporarily suspended.</p>
            ${reason ? `<p><strong>Reason:</strong> ${reason}</p>` : ''}
            <p>During the suspension period, you will not be able to access provider features.</p>
            <p>Please contact our support team to resolve this issue and restore your account.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth System. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Get MFA setup email template
  getMFASetupEmailTemplate(user) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>MFA Enabled</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #17a2b8; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Multi-Factor Authentication Enabled</h1>
          </div>
          <div class="content">
            <p>Hello ${user.first_name},</p>
            <p>Multi-Factor Authentication (MFA) has been successfully enabled on your account.</p>
            <p>Your account is now more secure with this additional layer of protection.</p>
            <p>You will need your authenticator app to generate codes when logging in.</p>
            <p>If you did not enable MFA, please contact support immediately.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth System. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Get security alert email template
  getSecurityAlertEmailTemplate(user, alertType, details) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Security Alert</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Security Alert</h1>
          </div>
          <div class="content">
            <p>Hello ${user.first_name},</p>
            <p>We detected suspicious activity on your account: <strong>${alertType}</strong></p>
            ${details.ipAddress ? `<p>IP Address: ${details.ipAddress}</p>` : ''}
            ${details.userAgent ? `<p>Device: ${details.userAgent}</p>` : ''}
            ${details.timestamp ? `<p>Time: ${details.timestamp}</p>` : ''}
            <p>If this was you, you can ignore this email. If not, please secure your account immediately by:</p>
            <ul>
              <li>Changing your password</li>
              <li>Enabling multi-factor authentication</li>
              <li>Reviewing your account activity</li>
            </ul>
            <p>Contact support if you need assistance.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth System. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Get GDPR export email template
  getGDPRExportEmailTemplate(user, downloadUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Data Export Ready</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #6f42c1; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .button { display: inline-block; padding: 12px 24px; background: #6f42c1; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Your Data Export is Ready</h1>
          </div>
          <div class="content">
            <p>Hello ${user.first_name},</p>
            <p>Your personal data export has been prepared and is ready for download.</p>
            <a href="${downloadUrl}" class="button">Download Your Data</a>
            <p>This download link will expire in 7 days for security reasons.</p>
            <p>The export contains all personal data we have on file for your account in JSON format.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth System. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Convert HTML to plain text
  htmlToText(html) {
    return html
      .replace(/<[^>]*>/g, '')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .trim();
  }
}

module.exports = new EmailService();