import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../database/prisma/prisma.service';
import { MailService } from '../../mail/mail.service';
import { UsersService } from '../../users/users.service';
import { LoggerService } from '../../utils/logger/logger.service';

export interface SessionInfo {
  id: string;
  sessionId: string;
  deviceInfo?: any;
  ipAddress?: string | null;
  userAgent?: string | null;
  location?: string | null;
  isActive: boolean;
  expiresAt: Date;
  lastActivity: Date;
  rememberMe: boolean;
  createdAt: Date;
  browserFingerprintHash?: string | null;
  deviceFingerprintConfidence?: number | null;
  latitude?: number | null;
  longitude?: number | null;
  timezone?: string | null;
  riskScore?: number;
  unusualActivityCount?: number;
  invalidatedAt?: Date | null;
  invalidationReason?: string | null;
}

@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly loggerService: LoggerService,
    private readonly mailService: MailService,
  ) {}

  /**
   * Get all active sessions for a user
   */
  async getActiveSessions(userId: string): Promise<SessionInfo[]> {
    try {
      const activeSessions = await this.prisma.userSession.findMany({
        where: {
          userId,
          isActive: true,
          expiresAt: { gt: new Date() },
        },
        select: {
          id: true,
          sessionId: true,
          deviceInfo: true,
          ipAddress: true,
          userAgent: true,
          location: true,
          isActive: true,
          expiresAt: true,
          lastActivity: true,
          rememberMe: true,
          createdAt: true,
          browserFingerprintHash: true,
          deviceFingerprintConfidence: true,
          latitude: true,
          longitude: true,
          timezone: true,
          riskScore: true,
          unusualActivityCount: true,
          invalidatedAt: true,
          invalidationReason: true,
        },
        orderBy: {
          lastActivity: 'desc',
        },
      });

      return activeSessions.map((session) => ({
        id: session.id,
        sessionId: session.sessionId,
        deviceInfo: session.deviceInfo,
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
        location: session.location,
        isActive: session.isActive,
        expiresAt: session.expiresAt,
        lastActivity: session.lastActivity,
        rememberMe: session.rememberMe,
        createdAt: session.createdAt,
        browserFingerprintHash: session.browserFingerprintHash,
        deviceFingerprintConfidence: session.deviceFingerprintConfidence,
        latitude: session.latitude,
        longitude: session.longitude,
        timezone: session.timezone,
        riskScore: session.riskScore,
        unusualActivityCount: session.unusualActivityCount,
        invalidatedAt: session.invalidatedAt,
        invalidationReason: session.invalidationReason,
      }));
    } catch (error) {
      this.logger.error(
        `Failed to get active sessions for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Invalidate a specific session
   */
  async invalidateSession(userId: string, sessionId: string): Promise<void> {
    try {
      const session = await this.prisma.userSession.findFirst({
        where: {
          userId,
          sessionId,
        },
      });

      if (!session) {
        throw new NotFoundException('Session not found');
      }

      // Delete all refresh tokens for this session
      await this.prisma.refreshToken.deleteMany({
        where: {
          sessionId: session.id,
        },
      });

      // Mark session as inactive
      await this.prisma.userSession.update({
        where: { id: session.id },
        data: { isActive: false },
      });

      // Log the invalidation
      await this.logAccessEvent(
        userId,
        'SESSION_INVALIDATED',
        session.sessionId,
      );

      this.logger.log(`✅ Invalidated session ${sessionId} for user ${userId}`);
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      this.logger.error(
        `Failed to invalidate session ${sessionId} for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Invalidate all other sessions except the current one
   */
  async invalidateOtherSessions(
    userId: string,
    currentSessionId: string,
  ): Promise<void> {
    try {
      // Get all active sessions except the current one
      const otherSessions = await this.prisma.userSession.findMany({
        where: {
          userId,
          isActive: true,
          sessionId: { not: currentSessionId },
        },
        select: { id: true, sessionId: true },
      });

      if (otherSessions.length === 0) {
        this.logger.log(`No other active sessions found for user ${userId}`);
        return;
      }

      const sessionIds = otherSessions.map((s) => s.id);

      // Delete refresh tokens for all other sessions
      await this.prisma.refreshToken.deleteMany({
        where: {
          sessionId: { in: sessionIds },
        },
      });

      // Mark all other sessions as inactive
      await this.prisma.userSession.updateMany({
        where: {
          id: { in: sessionIds },
        },
        data: { isActive: false },
      });

      // Log the invalidation for each session
      for (const session of otherSessions) {
        await this.logAccessEvent(
          userId,
          'SESSION_INVALIDATED',
          session.sessionId,
        );
      }

      this.logger.log(
        `✅ Invalidated ${otherSessions.length} other sessions for user ${userId}, kept session ${currentSessionId}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to invalidate other sessions for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Update session activity timestamp
   */
  async updateSessionActivity(sessionId: string): Promise<void> {
    try {
      await this.prisma.userSession.update({
        where: { id: sessionId },
        data: { lastActivity: new Date() },
      });
    } catch (error) {
      this.logger.warn(
        `Failed to update session activity for ${sessionId}:`,
        error.message,
      );
    }
  }

  /**
   * Clean up expired sessions and tokens (for maintenance)
   */
  async cleanupExpiredSessions(): Promise<{
    sessionsDeleted: number;
    tokensDeleted: number;
  }> {
    try {
      const now = new Date();

      // Find expired sessions
      const expiredSessions = await this.prisma.userSession.findMany({
        where: {
          OR: [{ expiresAt: { lt: now } }, { isActive: false }],
        },
        select: { id: true },
      });

      if (expiredSessions.length === 0) {
        return { sessionsDeleted: 0, tokensDeleted: 0 };
      }

      const sessionIds = expiredSessions.map((s) => s.id);

      // Delete refresh tokens for expired sessions
      const tokensDeleted = await this.prisma.refreshToken.deleteMany({
        where: {
          sessionId: { in: sessionIds },
        },
      });

      // Delete expired sessions
      await this.prisma.userSession.deleteMany({
        where: {
          id: { in: sessionIds },
        },
      });

      this.logger.log(
        `✅ Cleanup: Deleted ${expiredSessions.length} expired sessions and ${tokensDeleted.count} associated refresh tokens`,
      );

      return {
        sessionsDeleted: expiredSessions.length,
        tokensDeleted: tokensDeleted.count,
      };
    } catch (error) {
      this.logger.error('Failed to cleanup expired sessions:', error.message);
      throw error;
    }
  }

  /**
   * Log access events for audit and monitoring
   */
  async logAccessEvent(
    userId: string,
    event: string,
    sessionId?: string,
    ipAddress?: string,
    userAgent?: string,
    success = true,
    failureReason?: string,
  ): Promise<void> {
    try {
      await this.prisma.accessLog.create({
        data: {
          userId,
          event: event as any, // Cast to AccessEvent enum
          sessionId,
          ipAddress,
          userAgent,
          success,
          failureReason,
        },
      });
    } catch (error) {
      // Don't throw error for logging failures, just log it
      this.logger.warn(
        `Failed to log access event ${event} for user ${userId}:`,
        error.message,
      );
    }
  }

  /**
   * Get session health and security status
   */
  async getSessionHealth(userId: string): Promise<any> {
    try {
      const sessions = await this.getActiveSessions(userId);
      const totalSessions = sessions.length;
      const activeSessions = sessions.filter((s) => s.isActive).length;
      const averageRiskScore =
        sessions.reduce((sum, s) => sum + (s.riskScore || 0), 0) /
        totalSessions;
      const suspiciousActivities = sessions.reduce(
        (sum, s) => sum + (s.unusualActivityCount || 0),
        0,
      );
      const lastActivity =
        sessions.length > 0 ? sessions[0].lastActivity : null;

      const recommendations: string[] = [];
      if (averageRiskScore > 0.5) {
        recommendations.push(
          'High risk detected - review recent login activity',
        );
      }
      if (activeSessions > 3) {
        recommendations.push('Multiple active sessions detected');
      }
      if (suspiciousActivities > 0) {
        recommendations.push(
          `${suspiciousActivities} suspicious activities detected`,
        );
      }

      const healthData = {
        totalSessions,
        activeSessions,
        riskScore: Math.round(averageRiskScore * 100) / 100,
        suspiciousActivities,
        lastActivity,
        recommendations:
          recommendations.length > 0
            ? recommendations
            : ['Account security is good'],
      };

      return healthData;
    } catch (error) {
      this.logger.error('Failed to get session health:', error.message);
      throw error;
    }
  }

  /**
   * Revoke all sessions with high risk scores
   */
  async revokeSuspiciousSessions(
    userId: string,
    currentSessionId: string,
  ): Promise<any> {
    try {
      const sessions = await this.getActiveSessions(userId);
      const suspiciousSessions = sessions.filter(
        (s) => (s.riskScore || 0) >= 0.7,
      );

      let revokedCount = 0;
      for (const session of suspiciousSessions) {
        // Don't revoke current session
        if (session.sessionId !== currentSessionId) {
          await this.invalidateSession(userId, session.sessionId);
          revokedCount++;
        }
      }

      const remainingSessions = await this.getActiveSessions(userId);
      const remainingCount = remainingSessions.length;

      const result = {
        revokedCount,
        remainingSessions: remainingCount,
      };

      this.logger.log(
        `User ${userId} revoked ${revokedCount} suspicious sessions`,
      );
      return result;
    } catch (error) {
      this.logger.error('Failed to revoke suspicious sessions:', error.message);
      throw error;
    }
  }

  /**
   * Revoke sessions from specific geographic locations
   */
  async revokeSessionsByLocation(
    userId: string,
    currentSessionId: string,
    targetLocations: string[],
  ): Promise<any> {
    try {
      const sessions = await this.getActiveSessions(userId);

      let revokedCount = 0;
      for (const session of sessions) {
        // Don't revoke current session
        if (session.sessionId !== currentSessionId && session.location) {
          const sessionLocation = session.location.trim();
          if (
            targetLocations.some((target) => sessionLocation.includes(target))
          ) {
            await this.invalidateSession(userId, session.sessionId);
            revokedCount++;
          }
        }
      }

      const result = {
        revokedCount,
        targetLocations,
      };

      this.logger.log(
        `User ${userId} revoked ${revokedCount} sessions from locations: ${targetLocations.join(', ')}`,
      );
      return result;
    } catch (error) {
      this.logger.error(
        'Failed to revoke location-based sessions:',
        error.message,
      );
      throw error;
    }
  }

  /**
   * Get detailed security report for user sessions
   */
  async getSecurityReport(userId: string): Promise<any> {
    try {
      const sessions = await this.getActiveSessions(userId);
      const totalSessions = sessions.length;
      const activeSessions = sessions.filter((s) => s.isActive).length;

      const riskScores = sessions.map((s) => s.riskScore || 0);
      const averageRiskScore =
        riskScores.length > 0
          ? riskScores.reduce((sum, score) => sum + score, 0) /
            riskScores.length
          : 0;

      const totalSuspiciousActivities = sessions.reduce(
        (sum, s) => sum + (s.unusualActivityCount || 0),
        0,
      );

      const locations = [
        ...new Set(sessions.map((s) => s.location).filter(Boolean)),
      ];

      const riskDistribution = {
        low: sessions.filter((s) => (s.riskScore || 0) < 0.3).length,
        medium: sessions.filter(
          (s) => (s.riskScore || 0) >= 0.3 && (s.riskScore || 0) < 0.7,
        ).length,
        high: sessions.filter((s) => (s.riskScore || 0) >= 0.7).length,
      };

      const summary = {
        totalSessions,
        activeSessions,
        averageRiskScore: Math.round(averageRiskScore * 100) / 100,
        totalSuspiciousActivities,
      };

      const report = {
        summary,
        locations,
        riskDistribution,
        recentActivities: [], // Would need to fetch from access logs
      };

      return report;
    } catch (error) {
      this.logger.error('Failed to get security report:', error.message);
      throw error;
    }
  }

  /**
   * Send security alert notification to user
   */
  private async sendSecurityAlert(
    userId: string,
    alertType: string,
    details: any,
  ): Promise<void> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) return;

      // For now, we'll use the existing mail service to send alerts
      // In production, you might want to use push notifications, SMS, etc.

      const alertMessages = {
        NEW_DEVICE_LOGIN: {
          subject: 'New Device Login Detected',
          message: `A new device has logged into your account from ${details.location || 'an unknown location'}. If this wasn't you, please change your password immediately.`,
        },
        SUSPICIOUS_ACTIVITY: {
          subject: 'Suspicious Activity Detected',
          message: `We've detected suspicious activity on your account with a risk score of ${(details.riskScore * 100).toFixed(0)}%. Please review your recent sessions.`,
        },
        SESSION_REVOKED: {
          subject: 'Session Revoked',
          message: `One of your sessions has been revoked due to: ${details.reason}. If this wasn't you, please secure your account immediately.`,
        },
        PASSWORD_CHANGED: {
          subject: 'Password Changed',
          message:
            'Your password has been successfully changed. If you did not make this change, please contact support immediately.',
        },
      };

      const alert = alertMessages[alertType as keyof typeof alertMessages];
      if (alert) {
        await this.mailService.sendSecurityAlert(
          user.email,
          alert.subject,
          alert.message,
          details,
        );

        this.logger.log(`Security alert sent to ${user.email}: ${alertType}`);
      }
    } catch (error) {
      this.logger.warn(
        `Failed to send security alert to user ${userId}:`,
        error.message,
      );
    }
  }

  /**
   * Send session activity notification
   */
  async notifySessionActivity(
    userId: string,
    activity: string,
    sessionDetails: any,
  ): Promise<void> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) return;

      // Send notifications for important session activities
      const importantActivities = [
        'NEW_DEVICE_LOGIN',
        'MULTIPLE_FAILED_LOGINS',
        'SESSION_FROM_NEW_LOCATION',
        'ACCOUNT_RECOVERY_REQUESTED',
      ];

      if (importantActivities.includes(activity)) {
        await this.sendSecurityAlert(userId, activity, sessionDetails);
      }

      // Log the notification attempt
      this.loggerService.security(
        'SESSION_ACTIVITY_NOTIFICATION',
        {
          activity,
          sessionDetails,
          notificationSent: importantActivities.includes(activity),
        },
        userId,
      );
    } catch (error) {
      this.logger.warn(
        `Failed to send session activity notification to user ${userId}:`,
        error.message,
      );
    }
  }

  /**
   * Send account security summary (could be called periodically)
   */
  async sendSecuritySummary(userId: string): Promise<void> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) return;

      const sessions = await this.getActiveSessions(userId);
      const summary = {
        activeSessions: sessions.length,
        locations: [
          ...new Set(sessions.map((s) => s.location).filter(Boolean)),
        ],
        riskScore:
          sessions.reduce((sum, s) => sum + (s.riskScore || 0), 0) /
          sessions.length,
        lastActivity: sessions.length > 0 ? sessions[0].lastActivity : null,
      };

      await this.mailService.sendSecuritySummary(
        user.email,
        'Weekly Security Summary',
        summary,
      );

      this.logger.log(`Security summary sent to ${user.email}`);
    } catch (error) {
      this.logger.warn(
        `Failed to send security summary to user ${userId}:`,
        error.message,
      );
    }
  }
}
