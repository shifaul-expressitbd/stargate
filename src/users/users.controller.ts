// src/users/users.controller.ts
import {
  BadRequestException,
  Controller,
  Get,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { Request } from 'express';
import { User } from '../common/decorators/user.decorator';
import { ImpersonationGuard } from '../common/guards/impersonation.guard';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { UsersService } from './users.service';

interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  code?: string;
}

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  private createSuccessResponse<T>(message: string, data?: T): ApiResponse<T> {
    return { success: true, message, data };
  }

  @UseGuards(JwtAuthGuard, ImpersonationGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('profile')
  @ApiOperation({ summary: 'Get user profile with impersonation support' })
  @ApiResponse({
    status: 200,
    description: 'Profile retrieved successfully',
    schema: {
      example: {
        success: true,
        message: 'Profile retrieved successfully',
        data: {
          id: 'cmeiwdhbw0001jxvmdj1mq6r8',
          email: 'khanshifaul@gmail.com',
          name: 'Shifaul Khan',
          avatar: 'https://gravatar.com/avatar/...jpg',
          provider: 'local',
          isEmailVerified: true,
          isTwoFactorEnabled: false,
          roles: ['user'],
          createdAt: '2023-01-01T00:00:00.000Z',
          updatedAt: '2023-01-01T00:00:00.000Z',
          isImpersonation: false,
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Impersonated profile retrieved successfully',
    schema: {
      example: {
        success: true,
        message: 'Profile retrieved successfully',
        data: {
          id: 'target-user-id',
          email: 'target@example.com',
          name: 'Target User',
          avatar: 'https://gravatar.com/avatar/...jpg',
          provider: 'local',
          isEmailVerified: true,
          isTwoFactorEnabled: false,
          roles: ['user'],
          createdAt: '2023-01-01T00:00:00.000Z',
          updatedAt: '2023-01-01T00:00:00.000Z',
          isImpersonation: true,
          impersonatedBy: {
            id: 'admin-user-id',
            email: 'admin@example.com',
            name: 'Admin User',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
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
  async getProfile(
    @User() user: any,
    @Req() request: Request,
  ): Promise<ApiResponse> {
    let targetUserId: string | null = null;

    // Check for impersonation header (case-insensitive)
    const impersonateHeader =
      request.headers['x-impersonate-user'] ||
      request.headers['X-Impersonate-User'];

    if (impersonateHeader) {
      if (Array.isArray(impersonateHeader)) {
        targetUserId = impersonateHeader[0];
      } else {
        targetUserId = impersonateHeader;
      }
    }

    const userIdToQuery = targetUserId || user.id;
    const userData = await this.usersService.findById(userIdToQuery);

    if (!userData) {
      throw new BadRequestException('User not found');
    }

    // Remove sensitive fields
    const {
      password,
      verificationToken,
      twoFactorSecret,
      resetToken,
      resetTokenExpires,
      refreshTokenHash,
      ...profile
    } = userData;

    // Add impersonation context if applicable
    const responseData: any = {
      ...profile,
      isImpersonation: !!targetUserId,
    };

    if (targetUserId) {
      responseData.impersonatedBy = {
        id: user.id,
        email: user.email,
        name: user.name,
        roles: user.roles,
      };

      // Add audit info
      responseData.impersonationInfo = {
        initiatedAt: new Date().toISOString(),
        ipAddress: request.ip,
        userAgent: request.get('User-Agent'),
      };
    }

    return this.createSuccessResponse(
      'Profile retrieved successfully',
      responseData,
    );
  }
}
