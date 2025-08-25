// src/admin/admin.controller.ts
import {
  Body,
  Controller,
  Get,
  Logger,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { Request } from 'express';
import { Roles } from '../common/decorators/roles.decorator';
import { User } from '../common/decorators/user.decorator';
import { RolesGuard } from '../common/guards/roles.guard';
import { AdminService } from './admin.service';
import { ImpersonateDto, StopImpersonationDto } from './dto/impersonate.dto';

interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  code?: string;
}

@ApiTags('Impersonation')
@ApiBearerAuth('JWT-auth')
@UseGuards(RolesGuard)
@Roles('admin', 'crm_agent', 'developer') // Configurable via environment
@Controller('admin')
export class AdminController {
  private readonly logger = new Logger(AdminController.name);

  constructor(private readonly adminService: AdminService) {}

  private createSuccessResponse<T>(message: string, data?: T): ApiResponse<T> {
    return { success: true, message, data };
  }

  private createErrorResponse(
    message: string,
    code?: string,
    error?: string,
  ): ApiResponse {
    return { success: false, message, error, code };
  }

  @Post('impersonate')
  @ApiOperation({
    summary: 'Preview user data for impersonation',
    description:
      'Retrieves target user data without generating tokens. Useful for verifying the correct user before impersonation.',
  })
  @ApiBody({ type: ImpersonateDto })
  @ApiResponse({
    status: 200,
    description: 'User data retrieved successfully',
    schema: {
      example: {
        success: true,
        message: 'User data retrieved successfully',
        data: {
          targetUser: {
            id: 'c3a9b8e1-2c4d-4f5b-a6d8-1e2f3c4d5e6f',
            email: 'user@example.com',
            name: 'John Doe',
            roles: ['user'],
            isEmailVerified: true,
            isTwoFactorEnabled: false,
            createdAt: '2023-01-01T00:00:00.000Z',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 403,
    description: 'Insufficient permissions to impersonate',
    schema: {
      example: {
        success: false,
        message: 'Insufficient permissions to impersonate',
        error: 'FORBIDDEN',
        code: 'IMPERSONATION_DENIED',
      },
    },
  })
  async impersonateUser(
    @User() adminUser: any,
    @Body() impersonateDto: ImpersonateDto,
    @Req() req: Request,
  ): Promise<ApiResponse> {
    try {
      // Determine which identifier to use
      const targetIdentifier = impersonateDto.email || impersonateDto.userId;
      if (!targetIdentifier) {
        throw new Error('Either email or userId must be provided');
      }

      const result = await this.adminService.impersonateUser(
        adminUser.id,
        targetIdentifier,
        impersonateDto.reason,
        req.ip,
        req.get('User-Agent'),
      );

      return this.createSuccessResponse(
        'User data retrieved successfully',
        result,
      );
    } catch (error) {
      this.logger.error('Impersonation preview failed:', error.message);
      return this.createErrorResponse(
        error.message || 'Failed to retrieve user data',
        'IMPERSONATION_PREVIEW_FAILED',
        error.name || 'UNKNOWN_ERROR',
      );
    }
  }

  @Post('impersonate/generate-token')
  @ApiOperation({
    summary: 'Generate impersonation tokens',
    description:
      'Generates JWT tokens for impersonating another user. The generated tokens can be used to make API requests as the target user.',
  })
  @ApiBody({ type: ImpersonateDto })
  @ApiResponse({
    status: 200,
    description: 'Impersonation tokens generated successfully',
    schema: {
      example: {
        success: true,
        message: 'Impersonation tokens generated successfully',
        data: {
          accessToken:
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xeyJzdWIiOiJ0YXJnZXQtaWQiLCJlbWFpbCI6InRhcmdldEBleGFtcGxlLmNvbSIsImlzSW1wZXJzb25hdGlvbiI6dHJ1ZSwiaW1wZXJzb25hdGVkQnkiOiJhZG1pbi1pZCJ9.xACCESS_SIGNATURE',
          refreshToken:
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xeyJzdWIiOiJ0YXJnZXQtaWQiLCJlbWFpbCI6InRhcmdldEBleGFtcGxlLmNvbSIsImlzSW1wZXJzb25hdGlvbiI6dHJ1ZSwiaW1wZXJzb25hdGVkQnkiOiJhZG1pbi1pZCJ9.xREFRESH_SIGNATURE',
          expiresIn: 1800, // seconds
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Failed to generate tokens (e.g., invalid email or userId)',
    schema: {
      example: {
        success: false,
        message: 'Target user not found',
        error: 'BAD_REQUEST',
        code: 'USER_NOT_FOUND',
      },
    },
  })
  async generateImpersonationToken(
    @User() adminUser: any,
    @Body() impersonateDto: ImpersonateDto,
    @Req() req: Request,
  ): Promise<ApiResponse> {
    try {
      // Determine which identifier to use
      const targetIdentifier = impersonateDto.email || impersonateDto.userId;
      if (!targetIdentifier) {
        throw new Error('Either email or userId must be provided');
      }

      const tokens = await this.adminService.generateImpersonationToken(
        adminUser.id,
        targetIdentifier,
        adminUser.email,
        impersonateDto.reason,
        req.ip,
        req.get('User-Agent'),
      );

      return this.createSuccessResponse(
        'Impersonation tokens generated successfully',
        tokens,
      );
    } catch (error) {
      this.logger.error(
        'Impersonation token generation failed:',
        error.message,
      );
      return this.createErrorResponse(
        error.message || 'Failed to generate impersonation tokens',
        'TOKEN_GENERATION_FAILED',
        error.name || 'UNKNOWN_ERROR',
      );
    }
  }

  @Get('impersonate/status/:userId')
  @ApiOperation({ summary: 'Get current impersonation status of a user' })
  @ApiResponse({
    status: 200,
    description: 'Impersonation status retrieved',
    schema: {
      example: {
        success: true,
        message: 'Impersonation status retrieved',
        data: {
          isImpersonation: true,
          impersonatedBy: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
          impersonatorEmail: 'admin@example.com',
          impersonationExpiresAt: '2025-08-20T10:30:00.000Z',
          minutesRemaining: 25,
        },
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
    schema: {
      example: {
        success: false,
        message: 'User not found',
        error: 'NOT_FOUND',
        code: 'USER_NOT_FOUND',
      },
    },
  })
  async getImpersonationStatus(
    @Param('userId') userId: string,
  ): Promise<ApiResponse> {
    try {
      const status = await this.adminService.getImpersonationStatus(userId);
      return this.createSuccessResponse(
        'Impersonation status retrieved',
        status,
      );
    } catch (error) {
      this.logger.error(
        'Impersonation status retrieval failed:',
        error.message,
      );
      return this.createErrorResponse(
        error.message || 'Failed to retrieve impersonation status',
        'STATUS_RETRIEVAL_FAILED',
        error.name || 'UNKNOWN_ERROR',
      );
    }
  }

  @Post('impersonate/stop')
  @ApiOperation({ summary: 'Stop impersonating a user (end session)' })
  @ApiBody({ type: StopImpersonationDto })
  @ApiResponse({
    status: 200,
    description: 'Impersonation stopped successfully',
    schema: {
      example: {
        success: true,
        message: 'Impersonation stopped successfully',
      },
    },
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden – cannot stop impersonation (wrong admin)',
    schema: {
      example: {
        success: false,
        message: 'Cannot stop impersonation: not the original impersonator',
        error: 'FORBIDDEN',
        code: 'STOP_IMPERSONATION_DENIED',
      },
    },
  })
  async stopImpersonation(
    @User() adminUser: any,
    @Body() stopDto: StopImpersonationDto,
  ): Promise<ApiResponse> {
    try {
      await this.adminService.stopImpersonation(
        adminUser.id,
        stopDto.targetUserId,
      );
      return this.createSuccessResponse('Impersonation stopped successfully');
    } catch (error) {
      this.logger.error('Stop impersonation failed:', error.message);
      return this.createErrorResponse(
        error.message || 'Failed to stop impersonation',
        'STOP_IMPERSONATION_FAILED',
        error.name || 'UNKNOWN_ERROR',
      );
    }
  }
}
