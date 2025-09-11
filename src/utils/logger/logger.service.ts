import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as winston from 'winston';
import 'winston-daily-rotate-file';

@Injectable()
export class LoggerService {
  private logger: winston.Logger;

  constructor(private configService?: ConfigService) {
    // Use ConfigService if available, otherwise fallback to defaults
    const logLevel =
      this.configService?.get<string>('LOG_LEVEL', 'info') || 'info';
    const enableConsole =
      this.configService?.get<string>('LOG_CONSOLE', 'true') !== 'false';
    const logDir = this.configService?.get<string>('LOG_DIR', 'logs') || 'logs';

    const transports: winston.transport[] = [];

    // File transport with rotation for all logs
    transports.push(
      new winston.transports.DailyRotateFile({
        filename: `${logDir}/app-%DATE%.log`,
        datePattern: 'YYYY-MM-DD',
        maxSize: '20m',
        maxFiles: '14d',
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.errors({ stack: true }),
          winston.format.json(),
        ),
      }),
    );

    // File transport for error logs only
    transports.push(
      new winston.transports.DailyRotateFile({
        filename: `${logDir}/error-%DATE%.log`,
        datePattern: 'YYYY-MM-DD',
        level: 'error',
        maxSize: '20m',
        maxFiles: '30d',
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.errors({ stack: true }),
          winston.format.json(),
        ),
      }),
    );

    // Security events log
    transports.push(
      new winston.transports.DailyRotateFile({
        filename: `${logDir}/security-%DATE%.log`,
        datePattern: 'YYYY-MM-DD',
        level: 'info',
        maxSize: '20m',
        maxFiles: '90d',
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json(),
        ),
      }),
    );

    // Console transport if enabled
    if (enableConsole) {
      transports.push(
        new winston.transports.Console({
          level: logLevel,
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.timestamp(),
            winston.format.printf(
              ({ timestamp, level, message, context, ...meta }) => {
                const ctx = context ? `[${context}]` : '';
                const metaStr = Object.keys(meta).length
                  ? ` ${JSON.stringify(meta)}`
                  : '';
                return `${timestamp} ${level}${ctx}: ${message}${metaStr}`;
              },
            ),
          ),
        }),
      );
    }

    this.logger = winston.createLogger({
      level: logLevel,
      transports,
      exitOnError: false,
    });
  }

  // Standard logging methods
  info(message: string, context?: string, meta?: any) {
    this.logger.info(message, { context, ...meta });
  }

  error(message: string, context?: string, meta?: any) {
    this.logger.error(message, { context, ...meta });
  }

  warn(message: string, context?: string, meta?: any) {
    this.logger.warn(message, { context, ...meta });
  }

  debug(message: string, context?: string, meta?: any) {
    this.logger.debug(message, { context, ...meta });
  }

  // Security event logging
  security(event: string, details?: any, userId?: string, ipAddress?: string) {
    this.logger.info(`SECURITY: ${event}`, {
      context: 'Security',
      event,
      userId,
      ipAddress,
      timestamp: new Date().toISOString(),
      ...details,
    });
  }

  // Audit logging
  audit(action: string, userId?: string, resource?: string, details?: any) {
    this.logger.info(`AUDIT: ${action}`, {
      context: 'Audit',
      action,
      userId,
      resource,
      timestamp: new Date().toISOString(),
      ...details,
    });
  }

  // Login attempt logging
  loginAttempt(
    email: string,
    success: boolean,
    ipAddress?: string,
    userAgent?: string,
  ) {
    this.security('LOGIN_ATTEMPT', {
      email: this.sanitizeEmail(email),
      success,
      ipAddress,
      userAgent,
    });
  }

  // Failed authentication logging
  failedAuth(email: string, reason: string, ipAddress?: string) {
    this.security('FAILED_AUTH', {
      email: this.sanitizeEmail(email),
      reason,
      ipAddress,
    });
  }

  // Suspicious activity logging
  suspiciousActivity(activity: string, details?: any, ipAddress?: string) {
    this.security('SUSPICIOUS_ACTIVITY', {
      activity,
      ipAddress,
      ...details,
    });
  }

  // Sanitize sensitive data
  private sanitizeEmail(email: string): string {
    if (!email) return 'unknown';
    const [local, domain] = email.split('@');
    if (!domain) return 'invalid';
    return `${local.substring(0, 2)}***@${domain}`;
  }

  // Get child logger with context
  child(context: string): LoggerService {
    const childLogger = new LoggerService(this.configService);
    childLogger.logger = this.logger.child({ context });
    return childLogger;
  }
}
