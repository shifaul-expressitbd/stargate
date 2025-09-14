import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse as ApiResponseDecorator,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request } from 'express';

import { Public } from '../../common/decorators/public.decorator';
import { User } from '../../common/decorators/user.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { BaseController } from '../base/base.controller';
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
import { ApiResponse } from '../shared/interfaces/api-response.interface';

@ApiTags('Two-Factor Authentication')
@Controller('auth/2fa')
export class TwoFactorController extends BaseController {
  constructor(
    private readonly twoFactorService: TwoFactorService,
    private readonly authCoreService: AuthCoreService,
    private readonly sessionService: SessionService,
  ) {
    super();
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('generate')
  @ApiOperation({ summary: 'Generate 2FA secret for current user' })
  @ApiResponseDecorator({
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
      return super.createSuccessResponse(
        '2FA secret generated successfully',
        result,
      );
    } catch (error) {
      return this.handleServiceError(
        'generateTwoFactorSecret',
        error,
        'Failed to generate 2FA secret',
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
  @ApiResponseDecorator({
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
      return super.createSuccessResponse('2FA code is valid', { valid: true });
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error; // Keep input validation errors as HttpExceptions
      }

      return this.handleServiceError(
        'verifyTwoFactor',
        error,
        '2FA verification failed',
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
  @ApiResponseDecorator({
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

      return super.createSuccessResponse(
        '2FA enabled successfully',
        result || undefined,
      );
    } catch (error) {
      return this.handleServiceError(
        'enableTwoFactor',
        error,
        '2FA enable failed',
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
  @ApiResponseDecorator({
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

      return super.createSuccessResponse('2FA disabled successfully', result);
    } catch (error) {
      return this.handleServiceError(
        'disableTwoFactor',
        error,
        '2FA disable failed',
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
  @ApiResponseDecorator({
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

      return super.createSuccessResponse(
        'Backup codes regenerated successfully',
        result,
      );
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error; // Keep invalid verification code errors as HttpExceptions
      }

      return this.handleServiceError(
        'regenerateBackupCodes',
        error,
        'Backup codes regeneration failed',
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('status')
  @ApiOperation({ summary: 'Check 2FA status for current user' })
  @ApiResponseDecorator({
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
      return super.createSuccessResponse(
        '2FA status retrieved successfully',
        result,
      );
    } catch (error) {
      return this.handleServiceError(
        'getTwoFactorStatus',
        error,
        'Failed to get 2FA status',
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
  @ApiResponseDecorator({
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

      return super.createSuccessResponse(
        'Backup codes generated successfully',
        result,
      );
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error; // Keep invalid verification code errors as HttpExceptions
      }

      return this.handleServiceError(
        'generateBackupCodes',
        error,
        'Backup codes generation failed',
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
  @ApiResponseDecorator({
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
      this.logger.log(
        `🔐 TOTP login attempt - IP: ${req.ip}, User-Agent: ${req.get('User-Agent')}`,
      );
      this.logger.debug(
        `📝 Request payload: tempToken present: ${!!dto.tempToken}, totpCode length: ${dto.totpCode?.length}, rememberMe: ${dto.rememberMe}`,
      );
      this.logger.debug(
        `🔍 Request headers: Authorization: ${req.headers.authorization ? 'Present' : 'Missing'}, Content-Type: ${req.headers['content-type']}`,
      );
      this.logger.debug(`🔍 Request method: ${req.method}, URL: ${req.url}`);

      const result = await this.authCoreService.loginWithTwoFactor(
        dto,
        req.ip,
        req.get('User-Agent'),
      );
      this.logger.log(`✅ TOTP login successful`);
      return super.createSuccessResponse(
        'Two-factor authentication successful',
        result,
      );
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error; // Keep authentication errors as HttpExceptions
      }

      return this.handleServiceError(
        'loginWithTwoFactor',
        error,
        'TOTP login failed',
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
  @ApiResponseDecorator({
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

      return super.createSuccessResponse('Login successful with backup code', {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        remainingBackupCodes: 0, // This would need to be calculated
        message: 'Login successful with backup code',
      });
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error; // Keep invalid backup code errors as HttpExceptions
      }

      return this.handleServiceError(
        'loginWithBackupCode',
        error,
        'Backup code login failed',
      );
    }
  }
}
