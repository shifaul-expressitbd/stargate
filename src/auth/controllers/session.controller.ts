import {
  BadRequestException,
  Controller,
  Delete,
  Get,
  Logger,
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
import { SessionService } from '../services/session.service';

interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  code?: string;
}

@ApiTags('Session Management')
@Controller('auth/sessions')
export class SessionController {
  private readonly logger = new Logger(SessionController.name);

  constructor(private readonly sessionService: SessionService) {}

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
  async getActiveSessions(@User('id') userId: string): Promise<ApiResponse> {
    try {
      const sessions = await this.sessionService.getActiveSessions(userId);
      return this.createSuccessResponse(
        'Active sessions retrieved successfully',
        sessions,
      );
    } catch (error) {
      this.logger.error('Failed to get active sessions:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to get active sessions',
          'SESSION_ERROR',
          'GET_SESSIONS_FAILED',
        ),
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
  async getSessionHealth(@User('id') userId: string): Promise<ApiResponse> {
    try {
      const healthData = await this.sessionService.getSessionHealth(userId);
      return this.createSuccessResponse(
        'Session health retrieved successfully',
        healthData,
      );
    } catch (error) {
      this.logger.error('Failed to get session health:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to get session health',
          'SESSION_ERROR',
          'HEALTH_CHECK_FAILED',
        ),
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
  ): Promise<ApiResponse> {
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
        throw new NotFoundException(
          this.createErrorResponse(
            error.message,
            'SESSION_ERROR',
            'SESSION_NOT_FOUND',
          ),
        );
      }

      this.logger.error('Failed to invalidate session:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to invalidate session',
          'SESSION_ERROR',
          'INVALIDATE_SESSION_FAILED',
        ),
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
  async invalidateOtherSessions(@User() user: any): Promise<ApiResponse> {
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
      this.logger.error('Failed to invalidate other sessions:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to invalidate other sessions',
          'SESSION_ERROR',
          'INVALIDATE_OTHERS_FAILED',
        ),
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
  ): Promise<ApiResponse> {
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
      this.logger.error('Failed to revoke suspicious sessions:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to revoke suspicious sessions',
          'SESSION_ERROR',
          'REVOKE_SUSPICIOUS_FAILED',
        ),
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
  ): Promise<ApiResponse> {
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
      this.logger.error(
        'Failed to revoke location-based sessions:',
        error.message,
      );
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to revoke location-based sessions',
          'SESSION_ERROR',
          'REVOKE_LOCATION_FAILED',
        ),
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
  async getSecurityReport(@User('id') userId: string): Promise<ApiResponse> {
    try {
      const report = await this.sessionService.getSecurityReport(userId);
      return this.createSuccessResponse(
        'Security report retrieved successfully',
        report,
      );
    } catch (error) {
      this.logger.error('Failed to get security report:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to get security report',
          'SESSION_ERROR',
          'SECURITY_REPORT_FAILED',
        ),
      );
    }
  }
}
