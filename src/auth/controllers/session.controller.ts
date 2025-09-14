import {
  BadRequestException,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { Request } from 'express';

import { User } from '../../common/decorators/user.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { BaseController } from '../base/base.controller';
import { SessionService } from '../services/session.service';
import type { ApiResponse as ApiResponseType } from '../shared/interfaces/api-response.interface';

@ApiTags('Session Management')
@Controller('auth/sessions')
export class SessionController extends BaseController {
  constructor(private readonly sessionService: SessionService) {
    super();
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('')
  @ApiOperation({
    summary: 'Get all active sessions for the current user',
  })
  @ApiResponse({
    status: 200,
    description: 'Active sessions retrieved successfully',
    schema: {
      example: {
        success: true,
        message: 'Active sessions retrieved successfully',
        data: [
          {
            id: 'session-id',
            sessionId: 'session-uuid',
            deviceInfo: { browser: 'Chrome', os: 'Windows' },
            ipAddress: '192.168.1.1',
            userAgent: 'Mozilla/5.0...',
            location: 'New York, US',
            isActive: true,
            expiresAt: '2023-12-31T23:59:59.000Z',
            lastActivity: '2023-12-01T12:00:00.000Z',
            rememberMe: true,
            createdAt: '2023-11-30T10:00:00.000Z',
            riskScore: 0.2,
            unusualActivityCount: 0,
          },
        ],
      },
    },
  })
  async getActiveSessions(
    @User('id') userId: string,
  ): Promise<ApiResponseType> {
    try {
      const sessions = await this.sessionService.getActiveSessions(userId);
      return this.createSuccessResponse(
        'Active sessions retrieved successfully',
        sessions,
      );
    } catch (error) {
      return this.handleServiceError(
        'getActiveSessions',
        error,
        'Failed to get active sessions',
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('health')
  @ApiOperation({
    summary: 'Get session health and security status',
  })
  @ApiResponse({
    status: 200,
    description: 'Session health retrieved successfully',
    schema: {
      example: {
        success: true,
        message: 'Session health retrieved successfully',
        data: {
          totalSessions: 3,
          activeSessions: 2,
          riskScore: 0.15,
          suspiciousActivities: 0,
          lastActivity: '2023-12-01T12:00:00.000Z',
          recommendations: ['Consider enabling 2FA for additional security'],
        },
      },
    },
  })
  async getSessionHealth(@User('id') userId: string): Promise<ApiResponseType> {
    try {
      const healthData = await this.sessionService.getSessionHealth(userId);
      return this.createSuccessResponse(
        'Session health retrieved successfully',
        healthData,
      );
    } catch (error) {
      return this.handleServiceError(
        'getSessionHealth',
        error,
        'Failed to get session health',
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Delete(':sessionId')
  @ApiOperation({
    summary: 'Invalidate a specific session',
  })
  @ApiParam({
    name: 'sessionId',
    description: 'Session ID to invalidate',
    type: String,
  })
  @ApiResponse({
    status: 200,
    description: 'Session invalidated successfully',
    schema: {
      example: {
        success: true,
        message: 'Session invalidated successfully',
        data: null,
      },
    },
  })
  async invalidateSession(
    @User('id') userId: string,
    @Param('sessionId') sessionId: string,
    @Req() req: Request,
  ): Promise<ApiResponseType> {
    try {
      await this.sessionService.invalidateSession(userId, sessionId);

      // Log the session invalidation
      await this.sessionService.logAccessEvent(
        userId,
        'SESSION_INVALIDATED',
        sessionId,
        req.ip,
        req.get('User-Agent'),
      );

      this.logger.log(`Session ${sessionId} invalidated by user: ${userId}`);
      return this.createSuccessResponse('Session invalidated successfully');
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error; // Keep not found errors as HttpExceptions
      }

      return this.handleServiceError(
        'invalidateSession',
        error,
        'Failed to invalidate session',
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Delete('')
  @ApiOperation({
    summary: 'Invalidate all other active sessions except current',
  })
  @ApiResponse({
    status: 200,
    description: 'Other sessions invalidated successfully',
    schema: {
      example: {
        success: true,
        message: 'Other sessions invalidated successfully',
        data: null,
      },
    },
  })
  async invalidateOtherSessions(@User() user: any): Promise<ApiResponseType> {
    try {
      const currentSessionId = user.sessionId;
      await this.sessionService.invalidateOtherSessions(
        user.id,
        currentSessionId,
      );

      // Log the session invalidation
      await this.sessionService.logAccessEvent(
        user.id,
        'SESSION_INVALIDATED',
        currentSessionId,
      );

      this.logger.log(
        `Other sessions invalidated by user: ${user.email} (kept session: ${currentSessionId})`,
      );
      return this.createSuccessResponse(
        'Other sessions invalidated successfully',
      );
    } catch (error) {
      return this.handleServiceError(
        'invalidateOtherSessions',
        error,
        'Failed to invalidate other sessions',
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Delete('revoke-suspicious')
  @ApiOperation({
    summary: 'Revoke all sessions with high risk scores',
  })
  @ApiResponse({
    status: 200,
    description: 'Suspicious sessions revoked successfully',
    schema: {
      example: {
        success: true,
        message: 'Suspicious sessions revoked successfully',
        data: {
          revokedCount: 2,
          remainingSessions: 1,
        },
      },
    },
  })
  async revokeSuspiciousSessions(
    @User('id') userId: string,
    @User() user: any,
    @Req() req: Request,
  ): Promise<ApiResponseType> {
    try {
      const result = await this.sessionService.revokeSuspiciousSessions(
        userId,
        user.sessionId,
      );

      // Log the security action
      await this.sessionService.logAccessEvent(
        userId,
        'SECURITY_ALERT_TRIGGERED',
        user.sessionId,
        req.ip,
        req.get('User-Agent'),
      );

      this.logger.log(
        `User ${user.email} revoked ${result.revokedCount} suspicious sessions`,
      );
      return this.createSuccessResponse(
        'Suspicious sessions revoked successfully',
        result,
      );
    } catch (error) {
      return this.handleServiceError(
        'revokeSuspiciousSessions',
        error,
        'Failed to revoke suspicious sessions',
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Delete('revoke-by-location')
  @ApiOperation({
    summary: 'Revoke sessions from specific geographic locations',
  })
  @ApiQuery({
    name: 'locations',
    description: 'Comma-separated list of locations to revoke sessions from',
    required: true,
    type: String,
  })
  @ApiResponse({
    status: 200,
    description: 'Location-based sessions revoked successfully',
    schema: {
      example: {
        success: true,
        message: 'Location-based sessions revoked successfully',
        data: {
          revokedCount: 1,
          targetLocations: ['Unknown', 'New York, US'],
        },
      },
    },
  })
  async revokeSessionsByLocation(
    @User('id') userId: string,
    @User() user: any,
    @Query('locations') locationsQuery: string,
    @Req() req: Request,
  ): Promise<ApiResponseType> {
    try {
      if (!locationsQuery) {
        throw new BadRequestException('Locations parameter is required');
      }

      const targetLocations = locationsQuery
        .split(',')
        .map((loc) => loc.trim());

      const result = await this.sessionService.revokeSessionsByLocation(
        userId,
        user.sessionId,
        targetLocations,
      );

      // Log the security action
      await this.sessionService.logAccessEvent(
        userId,
        'GEOLOCATION_CHANGED',
        user.sessionId,
        req.ip,
        req.get('User-Agent'),
      );

      this.logger.log(
        `User ${user.email} revoked ${result.revokedCount} sessions from locations: ${targetLocations.join(', ')}`,
      );
      return this.createSuccessResponse(
        'Location-based sessions revoked successfully',
        result,
      );
    } catch (error) {
      return this.handleServiceError(
        'revokeSessionsByLocation',
        error,
        'Failed to revoke location-based sessions',
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('security-report')
  @ApiOperation({
    summary: 'Get detailed security report for user sessions',
  })
  @ApiResponse({
    status: 200,
    description: 'Security report retrieved successfully',
    schema: {
      example: {
        success: true,
        message: 'Security report retrieved successfully',
        data: {
          summary: {
            totalSessions: 5,
            activeSessions: 3,
            averageRiskScore: 0.15,
            totalSuspiciousActivities: 2,
          },
          locations: ['Dhaka, Bangladesh', 'New York, US', 'London, UK'],
          riskDistribution: {
            low: 3,
            medium: 1,
            high: 1,
          },
          recentActivities: [
            {
              event: 'DEVICE_FINGERPRINT_CHANGED',
              timestamp: '2023-12-01T12:00:00.000Z',
              ipAddress: '192.168.1.1',
            },
          ],
        },
      },
    },
  })
  async getSecurityReport(
    @User('id') userId: string,
  ): Promise<ApiResponseType> {
    try {
      const report = await this.sessionService.getSecurityReport(userId);
      return this.createSuccessResponse(
        'Security report retrieved successfully',
        report,
      );
    } catch (error) {
      return this.handleServiceError(
        'getSecurityReport',
        error,
        'Failed to get security report',
      );
    }
  }
}
