import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../database/prisma/prisma.service';
import { LoggerService } from '../../utils/logger/logger.service';

@Injectable()
export abstract class BaseService {
  protected readonly logger = new Logger(this.constructor.name);

  constructor(
    protected readonly prisma: PrismaService,
    protected readonly configService: ConfigService,
    protected readonly loggerService: LoggerService,
  ) {}

  protected logError(method: string, error: any, additionalInfo?: any): void {
    this.logger.error(`${method} failed:`, {
      error: error.message,
      stack: error.stack,
      additionalInfo,
    });
  }

  protected logInfo(method: string, message: string, data?: any): void {
    this.logger.log(`${method}: ${message}`, data);
  }

  protected logWarn(method: string, message: string, data?: any): void {
    this.logger.warn(`${method}: ${message}`, data);
  }

  protected handleDatabaseError(method: string, error: any): never {
    this.logError(method, error);

    if (error.code === 'P2002') {
      throw new Error('Resource already exists');
    }

    if (error.code === 'P2025') {
      throw new Error('Resource not found');
    }

    throw new Error('Database operation failed');
  }

  protected validateRequired(value: any, fieldName: string): void {
    if (!value || (typeof value === 'string' && value.trim().length === 0)) {
      throw new Error(`${fieldName} is required`);
    }
  }

  protected validateUUID(uuid: string, fieldName: string): void {
    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(uuid)) {
      throw new Error(`${fieldName} must be a valid UUID`);
    }
  }

  protected sanitizeInput(input: string): string {
    if (!input) return '';

    return input
      .trim()
      .replace(/[<>\"'&]/g, '') // Remove potentially dangerous characters
      .substring(0, 1000); // Limit length
  }

  protected async executeWithRetry<T>(
    operation: () => Promise<T>,
    maxRetries = 3,
    delay = 1000,
  ): Promise<T> {
    let lastError: any;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;

        if (attempt === maxRetries) {
          break;
        }

        this.logWarn(
          'executeWithRetry',
          `Attempt ${attempt} failed, retrying in ${delay}ms`,
          { error: error.message },
        );

        await new Promise((resolve) => setTimeout(resolve, delay));
        delay *= 2; // Exponential backoff
      }
    }

    throw lastError;
  }
}
