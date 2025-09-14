import { Logger } from '@nestjs/common';
import { ApiResponse } from '../shared/interfaces/api-response.interface';

export abstract class BaseController {
  protected readonly logger = new Logger(this.constructor.name);

  protected createSuccessResponse<T>(
    message: string,
    data?: T,
  ): ApiResponse<T> {
    return {
      success: true,
      message,
      data,
    };
  }

  protected createErrorResponse(
    message: string,
    error?: string,
    code?: string,
  ): ApiResponse {
    return {
      success: false,
      message,
      error,
      code,
    };
  }

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

  protected handleServiceError(
    method: string,
    error: any,
    customMessage?: string,
  ): ApiResponse {
    this.logError(method, error);

    // Handle specific error types
    if (error.message?.includes('not found')) {
      return this.createErrorResponse(
        customMessage || error.message,
        'NOT_FOUND',
        'RESOURCE_NOT_FOUND',
      );
    }

    if (
      error.message?.includes('unauthorized') ||
      error.message?.includes('invalid')
    ) {
      return this.createErrorResponse(
        customMessage || error.message,
        'UNAUTHORIZED',
        'AUTH_ERROR',
      );
    }

    if (error.message?.includes('forbidden')) {
      return this.createErrorResponse(
        customMessage || error.message,
        'FORBIDDEN',
        'ACCESS_DENIED',
      );
    }

    if (
      error.message?.includes('already exists') ||
      error.message?.includes('conflict')
    ) {
      return this.createErrorResponse(
        customMessage || error.message,
        'CONFLICT',
        'RESOURCE_EXISTS',
      );
    }

    // Default error response
    return this.createErrorResponse(
      customMessage || 'An unexpected error occurred',
      'INTERNAL_ERROR',
      'SERVER_ERROR',
    );
  }
}
