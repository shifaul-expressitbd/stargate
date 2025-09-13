import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request } from 'express';

import { Public } from '../../common/decorators/public.decorator';
import { User } from '../../common/decorators/user.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import {
  LoginWithBackupCodeDto,
  RegenerateBackupCodesDto,
} from '../dto/backup-code.dto';
import {
  EnableTwoFactorDto,
  GenerateBackupCodesDto,
  LoginWithTwoFactorDto,
  VerifyTwoFactorDto,
} from '../dto/two-factor.dto';
import { AuthCoreService } from '../services/auth-core.service';
import { SessionService } from '../services/session.service';
import { TwoFactorService } from '../services/two-factor.service';

interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  code?: string;
}

@ApiTags('Two-Factor Authentication')
@Controller('auth/2fa')
export class TwoFactorController {
  private readonly logger = new Logger(TwoFactorController.name);

  constructor(
    private readonly twoFactorService: TwoFactorService,
    private readonly authCoreService: AuthCoreService,
    private readonly sessionService: SessionService,
  ) { }

  private createSuccessResponse<T>(message: string, data?: T): ApiResponse<T> {
    return {
      success: true,
      message,
      data,
    };
  }

  private createErrorResponse(
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

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('generate')
  @ApiOperation({ summary: 'Generate 2FA secret for current user' })
  @ApiResponse({
    status: 200,
    description: '2FA secret generated',
    schema: {
      example: {
        success: true,
        message: '2FA secret generated successfully',
        data: {
          secret: 'base32-secret',
          qrCodeUrl: 'data:image/png;base64,...',
          manualEntryKey: 'base32-secret',
          otpAuthUrl: 'otpauth://totp/...',
        },
      },
    },
  })
  async generateTwoFactorSecret(
    @User('id') userId: string,
  ): Promise<ApiResponse> {
    try {
      const result =
        await this.twoFactorService.generateTwoFactorSecret(userId);
      return this.createSuccessResponse(
        '2FA secret generated successfully',
        result,
      );
    } catch (error) {
      this.logger.error('2FA secret generation failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to generate 2FA secret',
          '2FA_ERROR',
          'GENERATION_FAILED',
        ),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Post('verify')
  @ApiOperation({ summary: 'Verify a 2FA TOTP code' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['totpCode'],
      properties: {
        totpCode: {
          type: 'string',
          example: '123456',
          description: '6-digit TOTP code from authenticator app',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Code is valid',
    schema: {
      example: {
        success: true,
        message: '2FA code is valid',
        data: { valid: true },
      },
    },
  })
  async verifyTwoFactor(
    @User('id') userId: string,
    @Body() dto: VerifyTwoFactorDto,
  ): Promise<ApiResponse> {
    try {
      const isValid = await this.twoFactorService.verifyTwoFactorCode(
        userId,
        dto.totpCode,
      );
      if (!isValid) {
        throw new UnauthorizedException('Invalid 2FA code');
      }
      return this.createSuccessResponse('2FA code is valid', { valid: true });
    } catch (error) {
      this.logger.error('2FA verification failed:', error.message);
      throw new UnauthorizedException(
        this.createErrorResponse(error.message, '2FA_ERROR', 'INVALID_CODE'),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Throttle({ default: { limit: 3, ttl: 300 } })
  @Post('enable')
  @ApiOperation({ summary: 'Enable two-factor authentication' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['totpCode'],
      properties: {
        totpCode: {
          type: 'string',
          example: '123456',
          description: '6-digit TOTP code from authenticator app',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: '2FA enabled successfully',
    schema: {
      example: {
        success: true,
        message: '2FA enabled successfully',
        data: null,
      },
    },
  })
  async enableTwoFactor(
    @User('id') userId: string,
    @Body() dto: EnableTwoFactorDto,
    @Req() req: Request,
  ): Promise<ApiResponse> {
    try {
      const result = await this.twoFactorService.enableTwoFactor(
        userId,
        dto.totpCode,
      );

      // Log the 2FA enable event
      await this.sessionService.logAccessEvent(
        userId,
        'TWO_FACTOR_ENABLED',
        undefined,
        req.ip,
        req.get('User-Agent'),
      );

      return this.createSuccessResponse(
        '2FA enabled successfully',
        result || undefined,
      );
    } catch (error) {
      this.logger.error('2FA enable failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(error.message, '2FA_ERROR', 'ENABLE_FAILED'),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Throttle({ default: { limit: 3, ttl: 300 } })
  @Post('disable')
  @ApiOperation({ summary: 'Disable two-factor authentication' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['totpCode'],
      properties: {
        totpCode: {
          type: 'string',
          example: '123456',
          description: '6-digit TOTP code from authenticator app',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: '2FA disabled successfully',
    schema: {
      example: {
        success: true,
        message: '2FA disabled successfully',
        data: { success: true },
      },
    },
  })
  async disableTwoFactor(
    @User('id') userId: string,
    @Body() dto: EnableTwoFactorDto,
    @Req() req: Request,
  ): Promise<ApiResponse> {
    try {
      const result = await this.twoFactorService.disableTwoFactor(
        userId,
        dto.totpCode,
      );

      // Log the 2FA disable event
      await this.sessionService.logAccessEvent(
        userId,
        'TWO_FACTOR_DISABLED',
        undefined,
        req.ip,
        req.get('User-Agent'),
      );

      return this.createSuccessResponse('2FA disabled successfully', result);
    } catch (error) {
      this.logger.error('2FA disable failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(error.message, '2FA_ERROR', 'DISABLE_FAILED'),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Throttle({ default: { limit: 3, ttl: 300 } })
  @Post('regenerate-backup-codes')
  @ApiOperation({ summary: 'Regenerate new backup codes for 2FA' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['totpCode'],
      properties: {
        totpCode: {
          type: 'string',
          example: '123456',
          description: '6-digit TOTP code to verify regeneration',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Backup codes regenerated successfully',
    schema: {
      example: {
        success: true,
        message: 'Backup codes regenerated successfully',
        data: {
          backupCodes: ['NEWCODE1', 'NEWCODE2', 'NEWCODE3'],
        },
      },
    },
  })
  async regenerateBackupCodes(
    @User('id') userId: string,
    @Body() dto: RegenerateBackupCodesDto,
    @Req() req: Request,
  ): Promise<ApiResponse> {
    try {
      const result = await this.twoFactorService.regenerateBackupCodes(
        userId,
        dto,
      );

      // Log the backup code regeneration event
      await this.sessionService.logAccessEvent(
        userId,
        'BACKUP_CODE_USED',
        undefined,
        req.ip,
        req.get('User-Agent'),
      );

      return this.createSuccessResponse(
        'Backup codes regenerated successfully',
        result,
      );
    } catch (error) {
      this.logger.error('Backup codes regeneration failed:', error.message);

      if (error instanceof UnauthorizedException) {
        throw new UnauthorizedException(
          this.createErrorResponse(
            error.message,
            'UNAUTHORIZED',
            'INVALID_VERIFICATION_CODE',
          ),
        );
      }

      throw new BadRequestException(
        this.createErrorResponse(
          error.message,
          'REGENERATION_ERROR',
          'BACKUP_CODE_REGENERATION_FAILED',
        ),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('status')
  @ApiOperation({ summary: 'Check 2FA status for current user' })
  @ApiResponse({
    status: 200,
    description: '2FA status retrieved',
    schema: {
      example: {
        success: true,
        message: '2FA status retrieved successfully',
        data: {
          isEnabled: true,
          hasSecret: true,
        },
      },
    },
  })
  async getTwoFactorStatus(@User('id') userId: string): Promise<ApiResponse> {
    try {
      const result = await this.twoFactorService.getTwoFactorStatus(userId);
      return this.createSuccessResponse(
        '2FA status retrieved successfully',
        result,
      );
    } catch (error) {
      this.logger.error('2FA status check failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to get 2FA status',
          '2FA_ERROR',
          'STATUS_CHECK_FAILED',
        ),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Throttle({ default: { limit: 3, ttl: 300 } })
  @Post('generate-backup-codes')
  @ApiOperation({ summary: 'Generate new backup codes for 2FA' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['totpCode'],
      properties: {
        totpCode: {
          type: 'string',
          example: '123456',
          description: '6-digit TOTP code to verify generation',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Backup codes generated successfully',
    schema: {
      example: {
        success: true,
        message: 'Backup codes generated successfully',
        data: {
          backupCodes: ['ABCD1234', 'EFGH5678', 'IJKL9012'],
        },
      },
    },
  })
  async generateBackupCodes(
    @User('id') userId: string,
    @Body() dto: GenerateBackupCodesDto,
    @Req() req: Request,
  ): Promise<ApiResponse> {
    try {
      const result = await this.twoFactorService.generateBackupCodes(
        userId,
        dto,
      );

      // Log the backup code generation event
      await this.sessionService.logAccessEvent(
        userId,
        'BACKUP_CODE_USED',
        undefined,
        req.ip,
        req.get('User-Agent'),
      );

      return this.createSuccessResponse(
        'Backup codes generated successfully',
        result,
      );
    } catch (error) {
      this.logger.error('Backup codes generation failed:', error.message);

      if (error instanceof UnauthorizedException) {
        throw new UnauthorizedException(
          this.createErrorResponse(
            error.message,
            'UNAUTHORIZED',
            'INVALID_VERIFICATION_CODE',
          ),
        );
      }

      throw new BadRequestException(
        this.createErrorResponse(
          error.message,
          'GENERATION_ERROR',
          'BACKUP_CODE_GENERATION_FAILED',
        ),
      );
    }
  }

  // ========== PUBLIC 2FA ENDPOINTS ==========

  @Public()
  @Throttle({ default: { limit: 5, ttl: 300 } })
  @Post('login/totp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login using 2FA code' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['tempToken', 'totpCode'],
      properties: {
        tempToken: {
          type: 'string',
          example: 'eyJhbGciOi...',
          description: 'Temporary token from /login',
        },
        totpCode: {
          type: 'string',
          example: '123456',
          description: '6-digit TOTP code from authenticator app',
        },
        rememberMe: {
          type: 'boolean',
          example: true,
          description: 'Extend refresh token expiry if true',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Login successful with 2FA',
    schema: {
      example: {
        success: true,
        message: 'Two-factor authentication successful',
        data: {
          user: {
            id: 'uuid',
            email: 'user@example.com',
            name: 'John Doe',
            avatar: 'https://example.com/avatar.jpg',
            provider: 'local',
            isEmailVerified: true,
            isTwoFactorEnabled: true,
          },
          accessToken: 'jwt-token',
          refreshToken: 'refresh-token',
        },
      },
    },
  })
  async loginWithTwoFactor(
    @Body() dto: LoginWithTwoFactorDto,
    @Req() req: Request,
  ): Promise<ApiResponse> {
    try {
      this.logger.log(`🔐 TOTP login attempt - IP: ${req.ip}, User-Agent: ${req.get('User-Agent')}`);
      this.logger.debug(`📝 Request payload: tempToken present: ${!!dto.tempToken}, totpCode length: ${dto.totpCode?.length}, rememberMe: ${dto.rememberMe}`);
      this.logger.debug(`🔍 Request headers: Authorization: ${req.headers.authorization ? 'Present' : 'Missing'}, Content-Type: ${req.headers['content-type']}`);
      this.logger.debug(`🔍 Request method: ${req.method}, URL: ${req.url}`);

      const result = await this.authCoreService.loginWithTwoFactor(
        dto,
        req.ip,
        req.get('User-Agent'),
      );
      this.logger.log(`✅ TOTP login successful`);
      return this.createSuccessResponse(
        'Two-factor authentication successful',
        result,
      );
    } catch (error) {
      this.logger.error(`❌ TOTP login failed: ${error.message}`);
      this.logger.debug(`🔍 Error details:`, {
        statusCode: error.status,
        name: error.name,
        stack: error.stack
      });
      throw new UnauthorizedException(
        this.createErrorResponse(error.message, '2FA_ERROR', 'LOGIN_FAILED'),
      );
    }
  }

  @Public()
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('login/backup-code')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login using a backup code (for 2FA)' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['backupCode', 'tempToken'],
      properties: {
        backupCode: {
          type: 'string',
          example: 'ABCD1234',
          description: 'Backup code (8 characters alphanumeric)',
          minLength: 8,
          maxLength: 8,
          pattern: '^[A-Z0-9]{8}$',
        },
        tempToken: {
          type: 'string',
          example: 'eyJhbGciOi...',
          description: 'Temporary token from /login',
        },
        rememberMe: {
          type: 'boolean',
          example: true,
          description: 'Extend refresh token expiry if true',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Login successful with backup code',
    schema: {
      example: {
        success: true,
        message: 'Login successful with backup code',
        data: {
          user: {
            id: 'uuid',
            email: 'user@example.com',
            name: 'John Doe',
            avatar: 'https://example.com/avatar.jpg',
            provider: 'local',
            isEmailVerified: true,
            isTwoFactorEnabled: true,
          },
          accessToken: 'jwt-token',
          refreshToken: 'refresh-token',
          remainingBackupCodes: 7,
          message: 'Login successful with backup code',
        },
      },
    },
  })
  async loginWithBackupCode(
    @Body() loginWithBackupCodeDto: LoginWithBackupCodeDto,
    @Req() req: Request,
  ): Promise<ApiResponse> {
    try {
      const result = await this.authCoreService.loginWithBackupCode(
        loginWithBackupCodeDto.tempToken,
        loginWithBackupCodeDto.backupCode,
        loginWithBackupCodeDto.rememberMe,
        req.ip,
        req.get('User-Agent'),
      );

      return this.createSuccessResponse('Login successful with backup code', {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        remainingBackupCodes: 0, // This would need to be calculated
        message: 'Login successful with backup code',
      });
    } catch (error) {
      this.logger.error('Backup code login failed:', error.message);

      if (error instanceof UnauthorizedException) {
        throw new UnauthorizedException(
          this.createErrorResponse(
            error.message,
            'UNAUTHORIZED',
            'INVALID_BACKUP_CODE',
          ),
        );
      }

      throw new BadRequestException(
        this.createErrorResponse(
          'Backup code login failed',
          'AUTH_ERROR',
          'BACKUP_CODE_LOGIN_FAILED',
        ),
      );
    }
  }
}
