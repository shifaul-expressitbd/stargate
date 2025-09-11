import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { UrlConfigService } from '../config/url.config';

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
}

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private transporter: nodemailer.Transporter;

  constructor(
    private readonly configService: ConfigService,
    private readonly urlConfigService?: UrlConfigService,
  ) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get('SMTP_HOST', 'smtp.gmail.com'),
      port: parseInt(this.configService.get('SMTP_PORT', '587')),
      secure: false,
      auth: {
        user: this.configService.get('SMTP_USER'),
        pass: this.configService.get('SMTP_PASS'),
      },
    });
  }

  async sendVerificationEmail(email: string, token: string): Promise<void> {
    // Use the backend API endpoint for verification
    const verifyUrl =
      this.urlConfigService?.getEmailVerificationUrl(token) ||
      `${this.configService.get('FRONTEND_URL', 'http://localhost:5555')}/api/auth/verify-email?token=${token}`;

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Verify Your Email</title>
      </head>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="margin: 0; font-size: 28px;">Welcome to StarGate! 🚀</h1>
        </div>
        
        <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
          <h2 style="color: #333; margin-top: 0;">Verify Your Email Address</h2>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            Thank you for registering! Please verify your email address by clicking the button below:
          </p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verifyUrl}" 
               style="background: #28a745; color: white; padding: 15px 30px; text-decoration: none; 
                      border-radius: 5px; font-weight: bold; display: inline-block; font-size: 16px;">
              Verify Email Address
            </a>
          </div>
          
          <p style="color: #666; font-size: 14px;">
            If the button doesn't work, you can also copy and paste this link into your browser:
          </p>
          <p style="color: #007bff; word-break: break-all; font-size: 14px;">
            ${verifyUrl}
          </p>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
          
          <p style="color: #999; font-size: 12px;">
            ⏰ This link will expire in 24 hours.<br>
            🔒 If you didn't request this, please ignore this email.<br>
            💡 Need help? Contact our support team.
          </p>
        </div>
      </body>
      </html>
    `;

    const mailOptions: EmailOptions = {
      to: email,
      subject: '🔐 Verify Your Email Address - StarGate',
      html,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`✅ Verification email sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `❌ Failed to send verification email to ${email}:`,
        error instanceof Error ? error.message : String(error),
      );
      throw new Error('Email sending failed');
    }
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const resetUrl =
      this.urlConfigService?.getPasswordResetUrl(token) ||
      `${this.configService.get('FRONTEND_URL', 'http://localhost:5173')}/reset-password?token=${token}`;

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Reset Your Password</title>
      </head>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="margin: 0; font-size: 28px;">Password Reset Request 🔒</h1>
        </div>
        
        <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
          <h2 style="color: #333; margin-top: 0;">Reset Your Password</h2>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            We received a request to reset your password. Click the button below to create a new password:
          </p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" 
               style="background: #dc3545; color: white; padding: 15px 30px; text-decoration: none; 
                      border-radius: 5px; font-weight: bold; display: inline-block; font-size: 16px;">
              Reset Password
            </a>
          </div>
          
          <p style="color: #666; font-size: 14px;">
            If the button doesn't work, copy and paste this link into your browser:
          </p>
          <p style="color: #007bff; word-break: break-all; font-size: 14px;">
            ${resetUrl}
          </p>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
          
          <p style="color: #999; font-size: 12px;">
            ⏰ This link will expire in 1 hour.<br>
            🔒 If you didn't request this, please ignore this email - your password won't be changed.<br>
            💡 Need help? Contact our support team.
          </p>
        </div>
      </body>
      </html>
    `;

    const mailOptions: EmailOptions = {
      to: email,
      subject: '🔑 Reset Your Password - StarGate',
      html,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`✅ Password reset email sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `❌ Failed to send password reset email to ${email}:`,
        error instanceof Error ? error.message : String(error),
      );
      throw new Error('Password reset email sending failed');
    }
  }

  async sendSecurityAlert(
    email: string,
    subject: string,
    message: string,
    details?: any,
  ): Promise<void> {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Security Alert</title>
      </head>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="margin: 0; font-size: 28px;">Security Alert ⚠️</h1>
        </div>

        <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
          <h2 style="color: #333; margin-top: 0;">${subject}</h2>
          <p style="color: #666; font-size: 16px; line-height: 1.6;">
            ${message}
          </p>

          ${
            details
              ? `
          <div style="background: #fff; padding: 15px; border-radius: 5px; border-left: 4px solid #ff6b6b; margin: 20px 0;">
            <h3 style="margin-top: 0; color: #333;">Details:</h3>
            <pre style="color: #666; font-size: 14px; white-space: pre-wrap;">${JSON.stringify(details, null, 2)}</pre>
          </div>
          `
              : ''
          }

          <div style="text-align: center; margin: 30px 0;">
            <a href="${this.configService.get('FRONTEND_URL', 'http://localhost:5173')}/account/security"
               style="background: #dc3545; color: white; padding: 15px 30px; text-decoration: none;
                      border-radius: 5px; font-weight: bold; display: inline-block; font-size: 16px;">
              Review Account Security
            </a>
          </div>

          <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">

          <p style="color: #999; font-size: 12px;">
            🔒 If this wasn't you, please change your password immediately.<br>
            💡 Need help? Contact our support team.<br>
            📧 This is an automated security notification.
          </p>
        </div>
      </body>
      </html>
    `;

    const mailOptions: EmailOptions = {
      to: email,
      subject: `🚨 ${subject} - StarGate Security`,
      html,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`✅ Security alert sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `❌ Failed to send security alert to ${email}:`,
        error instanceof Error ? error.message : String(error),
      );
      throw new Error('Security alert email sending failed');
    }
  }

  async sendSecuritySummary(
    email: string,
    subject: string,
    summary: any,
  ): Promise<void> {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Security Summary</title>
      </head>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="margin: 0; font-size: 28px;">Security Summary 📊</h1>
        </div>

        <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
          <h2 style="color: #333; margin-top: 0;">${subject}</h2>

          <div style="background: #fff; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <h3 style="margin-top: 0; color: #333;">Account Overview</h3>
            <ul style="color: #666;">
              <li><strong>Active Sessions:</strong> ${summary.activeSessions || 0}</li>
              <li><strong>Risk Score:</strong> ${(summary.riskScore * 100 || 0).toFixed(1)}%</li>
              <li><strong>Locations:</strong> ${summary.locations?.join(', ') || 'None'}</li>
              <li><strong>Last Activity:</strong> ${summary.lastActivity ? new Date(summary.lastActivity).toLocaleString() : 'None'}</li>
            </ul>
          </div>

          <div style="text-align: center; margin: 30px 0;">
            <a href="${this.configService.get('FRONTEND_URL', 'http://localhost:5173')}/account/sessions"
               style="background: #007bff; color: white; padding: 15px 30px; text-decoration: none;
                      border-radius: 5px; font-weight: bold; display: inline-block; font-size: 16px;">
              Manage Sessions
            </a>
          </div>

          <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">

          <p style="color: #999; font-size: 12px;">
            🔒 Keep your account secure by regularly reviewing your sessions.<br>
            💡 Enable two-factor authentication for additional security.<br>
            📧 This is an automated security summary.
          </p>
        </div>
      </body>
      </html>
    `;

    const mailOptions: EmailOptions = {
      to: email,
      subject: `📊 ${subject} - StarGate Security`,
      html,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`✅ Security summary sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `❌ Failed to send security summary to ${email}:`,
        error instanceof Error ? error.message : String(error),
      );
      throw new Error('Security summary email sending failed');
    }
  }
}
