// src/admin/admin.service.ts
import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../database/prisma/prisma.service';
import { UsersService } from '../users/users.service';
import { ActiveImpersonationSession } from './interfaces/impersonation-session.interface';
import { ImpersonationAuditLog } from './interfaces/impersonation-audit.interface';

@Injectable()
export class AdminService {
  private readonly logger = new Logger(AdminService.name);
  
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  private canImpersonate(roles: string[]): boolean {
    const allowedRoles = this.configService.get<string[]>('IMPERSONATION_ALLOWED_ROLES', ['admin']);
    return roles.some(role => allowedRoles.includes(role));
  }

  async impersonateUser(
    adminUserId: string, 
    targetIdentifier: string, // Can be either email or userId
    reason?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ targetUser: any }> {
    const adminUser = await this.usersService.findById(adminUserId);
    if (!adminUser) {
      throw new NotFoundException('Admin user not found');
    }
    
    if (!this.canImpersonate(adminUser.roles)) {
      throw new BadRequestException('Insufficient permissions to impersonate');
    }

    let targetUser: any = null;
    
    // Determine if identifier is email or userId
    if (targetIdentifier.includes('@')) {
      targetUser = await this.usersService.findByEmail(targetIdentifier);
    } else {
      targetUser = await this.usersService.findById(targetIdentifier);
    }

    if (!targetUser) {
      throw new NotFoundException('Target user not found');
    }

    // Create audit log entry with timestamp
    await this.auditImpersonation({
      adminId: adminUser.id,
      adminEmail: adminUser.email,
      targetId: targetUser.id,
      targetEmail: targetUser.email,
      action: 'start',
      reason,
      ipAddress,
      userAgent,
      timestamp: new Date(),
    });

    // Store active impersonation session in database
    const impersonationTimeout = this.configService.get<number>('IMPERSONATION_TIMEOUT_MINUTES', 60);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + impersonationTimeout * 60 * 1000);

    await this.prisma.impersonationSession.upsert({
      where: { targetId: targetUser.id },
      update: {
        adminId: adminUser.id,
        startedAt: now,
        expiresAt,
        reason,
        ipAddress,
        userAgent,
      },
      create: {
        adminId: adminUser.id,
        targetId: targetUser.id,
        startedAt: now,
        expiresAt,
        reason,
        ipAddress,
        userAgent,
      },
    });

    // Remove sensitive data from response
    const { password, verificationToken, twoFactorSecret, ...sanitizedUser } = targetUser;
    
    return { targetUser: sanitizedUser };
  }

  async generateImpersonationToken(
    adminUserId: string,
    targetIdentifier: string, // Can be either email or userId
    adminEmail: string,
    reason?: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    const adminUser = await this.usersService.findById(adminUserId);
    if (!adminUser) {
      throw new NotFoundException('Admin user not found');
    }
    
    if (!this.canImpersonate(adminUser.roles)) {
      throw new BadRequestException('Insufficient permissions to impersonate');
    }

    let targetUser: any = null;
    
    // Determine if identifier is email or userId
    if (targetIdentifier.includes('@')) {
      targetUser = await this.usersService.findByEmail(targetIdentifier);
    } else {
      targetUser = await this.usersService.findById(targetIdentifier);
    }

    if (!targetUser) {
      throw new NotFoundException('Target user not found');
    }

    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');
    const impersonationTimeout = this.configService.get<number>('IMPERSONATION_TIMEOUT_MINUTES', 60);

    if (!jwtSecret || !refreshSecret) {
      throw new Error('JWT secrets not configured');
    }

    // Create JWT payload with impersonation context
    const payload = {
      sub: targetUser.id,
      email: targetUser.email,
      roles: targetUser.roles,
      impersonatedBy: adminUserId,
      impersonatorEmail: adminEmail,
      isImpersonation: true,
    };

    // Generate access token with shorter expiration for impersonation
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: jwtSecret,
      expiresIn: `${impersonationTimeout}m`,
    });

    // Generate refresh token with slightly longer expiration
    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: refreshSecret,
      expiresIn: `${impersonationTimeout + 60}m`, // 1 hour longer than access token
    });

    // Create audit log entry with timestamp
    await this.auditImpersonation({
      adminId: adminUserId,
      adminEmail,
      targetId: targetUser.id,
      targetEmail: targetUser.email,
      action: 'start',
      reason,
      ipAddress,
      userAgent,
      timestamp: new Date(),
    });

    // Store active impersonation session
    const now = new Date();
    const expiresAt = new Date(now.getTime() + impersonationTimeout * 60 * 1000);

    await this.prisma.impersonationSession.upsert({
      where: { targetId: targetUser.id },
      update: {
        adminId: adminUserId,
        startedAt: now,
        expiresAt,
        reason,
        ipAddress,
        userAgent,
      },
      create: {
        adminId: adminUserId,
        targetId: targetUser.id,
        startedAt: now,
        expiresAt,
        reason,
        ipAddress,
        userAgent,
      },
    });

    this.logger.log(`Admin ${adminEmail} generated impersonation tokens for user ${targetUser.email}`);

    return {
      accessToken,
      refreshToken,
      expiresIn: impersonationTimeout * 60, // Return seconds
    };
  }

  async getImpersonationStatus(userId: string): Promise<{
    isImpersonation: boolean;
    impersonatedBy?: string;
    impersonatorEmail?: string;
    impersonationExpiresAt?: Date;
    minutesRemaining?: number;
  }> {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check database for active impersonation session
    const session = await this.prisma.impersonationSession.findUnique({
      where: { targetId: userId },
    });

    if (!session || session.expiresAt.getTime() <= Date.now()) {
      // Clean up expired session if it exists
      if (session) {
        await this.prisma.impersonationSession.delete({
          where: { targetId: userId },
        });
      }
      return { isImpersonation: false };
    }

    const minutesRemaining = Math.max(0, Math.floor((session.expiresAt.getTime() - Date.now()) / 60000));

    return {
      isImpersonation: true,
      impersonatedBy: session.adminId,
      impersonatorEmail: (await this.usersService.findById(session.adminId))?.email,
      impersonationExpiresAt: session.expiresAt,
      minutesRemaining,
    };
  }

  async stopImpersonation(adminUserId: string, targetUserId: string): Promise<void> {
    // Verify that the admin stopping impersonation is the same one who started it
    const session = await this.prisma.impersonationSession.findUnique({
      where: { targetId: targetUserId },
    });

    if (!session) {
      this.logger.warn(`Attempt to stop non-existent impersonation session for user ${targetUserId}`);
      return; // Idempotent - returning success if session doesn't exist
    }

    if (session.adminId !== adminUserId) {
      throw new BadRequestException('Cannot stop impersonation: not the original impersonator');
    }

    // Create audit log entry with timestamp
    const targetUser = await this.usersService.findById(targetUserId);
    const adminUser = await this.usersService.findById(adminUserId);
    
    await this.auditImpersonation({
      adminId: adminUserId,
      adminEmail: adminUser?.email || 'unknown',
      targetId: targetUserId,
      targetEmail: targetUser?.email || 'unknown',
      action: 'stop',
      ipAddress: session.ipAddress || 'unknown',
      userAgent: session.userAgent || 'unknown',
      timestamp: new Date(),
    });

    // Remove the active impersonation session
    await this.prisma.impersonationSession.delete({
      where: { targetId: targetUserId },
    });

    this.logger.log(`Impersonation stopped: Admin ${adminUserId} -> User ${targetUserId}`);
  }

  private async auditImpersonation(logData: ImpersonationAuditLog): Promise<void> {
    try {
      // Save to database
      await this.prisma.impersonationAudit.create({
        data: {
          adminId: logData.adminId,
          adminEmail: logData.adminEmail,
          targetId: logData.targetId,
          targetEmail: logData.targetEmail,
          action: logData.action,
          reason: logData.reason,
          ipAddress: logData.ipAddress,
          userAgent: logData.userAgent,
          timestamp: logData.timestamp,
        },
      });

      // Also log to console for immediate visibility
      this.logger.log(`IMPERSONATION_AUDIT: ${logData.action.toUpperCase()} - ` +
        `Admin: ${logData.adminId} (${logData.adminEmail}), ` +
        `Target: ${logData.targetId} (${logData.targetEmail}), ` +
        `IP: ${logData.ipAddress || 'unknown'}, ` +
        `User-Agent: ${logData.userAgent || 'unknown'}, ` +
        `Reason: ${logData.reason || 'N/A'}`);
      
      // In production, you might also send this to an external logging service
      // like ELK, Splunk, or cloud logging
    } catch (error) {
      this.logger.error('Failed to create impersonation audit log entry:', error);
      // Don't throw error as auditing shouldn't block the main operation
    }
  }
}