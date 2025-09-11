import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { google } from 'googleapis';
import { authenticator, totp } from 'otplib';
import QRCode from 'qrcode-generator';
import { LoggerService } from 'src/utils/logger/logger.service';
import { PrismaService } from '../database/prisma/prisma.service';
import { MailService } from '../mail/mail.service';
import { UsersService } from '../users/users.service';
import { RegenerateBackupCodesDto } from './dto/backup-code.dto';
import { RegisterDto } from './dto/register.dto';
import {
  GenerateBackupCodesDto,
  LoginWithTwoFactorDto,
} from './dto/two-factor.dto';

// Temporary type definitions until Prisma client generates
interface UserSession {
  id: string;
  userId: string;
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
  updatedAt: Date;
  refreshTokens?: RefreshToken[];
}

interface RefreshToken {
  id: string;
  sessionId: string;
  tokenHash: string;
  tokenFamily: string | null;
  isActive: boolean;
  usedAt?: Date | null;
  expiresAt: Date;
  ipAddress?: string | null;
  userAgent?: string | null;
  createdAt: Date;
  updatedAt: Date;
  session?: UserSession;
}

export interface JwtPayload {
  sub: string;
  email: string;
  roles?: string[]; // Optional for permission tokens
  type?: string; // Added for permission tokens (gtm-permission)
  permissions?: string[]; // Added for permission tokens
  iat?: number;
  exp?: number;
  impersonatedBy?: string;
  rememberMe?: boolean;
  impersonatorEmail?: string;
  isImpersonation?: boolean;
  // New properties for refresh token management
  sessionId?: string;
  tokenFamily?: string;
}

export interface AuthResponse {
  user: {
    id: string;
    email: string;
    name: string;
    avatar?: string | null;
    provider: string;
    isEmailVerified: boolean;
    isTwoFactorEnabled: boolean;
  };
  accessToken: string;
  refreshToken: string;
}

export interface TwoFactorRequiredResponse {
  requiresTwoFactor: true;
  userId: string;
  email: string;
  tempToken: string;
}

export interface TwoFactorGenerateResponse {
  secret: string;
  qrCodeUrl: string;
  manualEntryKey: string;
  otpAuthUrl: string;
}

export interface TwoFactorEnableResponse {
  backupCodes?: string[];
}

export interface TwoFactorStatusResponse {
  isEnabled: boolean;
  hasSecret: boolean;
}

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

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  session: SessionInfo;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly appName = 'StarGate Platform';

  // GTM Permission Token Configuration
  private readonly GTM_PERMISSIONS = [
    'gtm.accounts.read',
    'gtm.containers.read',
    'gtm.tags.read',
  ] as const;

  private readonly GTM_TOKEN_TYPE = 'gtm-permission';
  private readonly GTM_TOKEN_EXPIRY = '15m';

  private readonly totpOptions = {
    window: 3,
    step: 30,
  };

  private readonly enhancedTotpConfig = {
    algorithm: 'SHA1' as const,
    digits: 6,
    step: 30,
    window: 3,
  };

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    private readonly prisma: PrismaService,
    private readonly loggerService: LoggerService,
  ) {
    this.validateJWTSecrets();

    authenticator.options = {
      ...this.totpOptions,
    };

    totp.options = {
      ...this.totpOptions,
    };
  }

  async getGoogleOAuth2Client() {
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = this.configService.get<string>('GOOGLE_CLIENT_SECRET');
    const callbackUrl = this.configService.get<string>('GOOGLE_CALLBACK_URL');

    if (!clientId || !clientSecret || !callbackUrl) {
      throw new UnauthorizedException('Google OAuth is not configured');
    }

    const oauth2Client = new google.auth.OAuth2(
      clientId,
      clientSecret,
      callbackUrl,
    );

    // Add GTM scopes
    oauth2Client.credentials = {
      scope:
        'https://www.googleapis.com/auth/tagmanager.readonly https://www.googleapis.com/auth/tagmanager.edit.containers https://www.googleapis.com/auth/tagmanager.manage.accounts',
    };

    return oauth2Client;
  }

  async getGoogleTokens(userId: string) {
    const provider = await this.prisma.authProvider.findUnique({
      where: {
        userId_provider: {
          userId,
          provider: 'GOOGLE',
        },
      },
    });

    if (!provider || !provider.accessToken) {
      throw new UnauthorizedException(
        'Google OAuth tokens not found. Please authenticate with Google first.',
      );
    }

    // Return only the access token since the auth module handles token refresh
    return {
      accessToken: provider.accessToken,
    };
  }

  private validateJWTSecrets() {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const jwtRefreshSecret =
      this.configService.get<string>('JWT_REFRESH_SECRET');

    // Enhanced logging for debugging test issues
    this.logger.log(
      `🔐 [AuthService] Validating JWT secrets at ${new Date().toISOString()}`,
    );
    this.logger.log(
      `🔐 [AuthService] JWT_SECRET length: ${jwtSecret?.length || 'undefined'}`,
    );
    this.logger.log(
      `🔐 [AuthService] JWT_REFRESH_SECRET length: ${jwtRefreshSecret?.length || 'undefined'}`,
    );

    if (!jwtSecret || jwtSecret.length < 32) {
      this.logger.error(
        `❌ [AuthService] JWT_SECRET validation failed: ${!jwtSecret ? 'NOT FOUND' : `too short (${jwtSecret.length} chars)`}`,
      );
      throw new Error(
        `JWT_SECRET is missing or too short (minimum 32 characters). Found length: ${jwtSecret?.length || 'undefined'}`,
      );
    }
    if (!jwtRefreshSecret || jwtRefreshSecret.length < 32) {
      this.logger.error(
        `❌ [AuthService] JWT_REFRESH_SECRET validation failed: ${!jwtRefreshSecret ? 'NOT FOUND' : `too short (${jwtRefreshSecret.length} chars)`}`,
      );
      throw new Error(
        `JWT_REFRESH_SECRET is missing or too short (minimum 32 characters). Found length: ${jwtRefreshSecret?.length || 'undefined'}`,
      );
    }

    this.logger.log('✅ [AuthService] JWT secrets validated successfully');
  }

  async validateUser(email: string, password: string): Promise<any> {
    try {
      const user = await this.usersService.findByEmail(email);
      if (!user) throw new UnauthorizedException('Invalid credentials');
      if (!user.isEmailVerified)
        throw new UnauthorizedException('Please verify your email');
      if (!user.password)
        throw new UnauthorizedException('Login with social account');

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid)
        throw new UnauthorizedException('Invalid credentials');

      // Ensure LOCAL auth provider exists for the user
      const existingLocalProvider = await this.prisma.authProvider.findUnique({
        where: {
          userId_provider: {
            userId: user.id,
            provider: this.mapStringToProviderEnum('local'),
          },
        },
      });

      if (!existingLocalProvider) {
        // Create LOCAL auth provider if it doesn't exist
        await this.prisma.authProvider.create({
          data: {
            userId: user.id,
            provider: this.mapStringToProviderEnum('local'),
            providerId: user.email,
            email: user.email,
            isPrimary: false, // Don't override existing primary provider
          },
        });
        this.logger.log(`✅ Created LOCAL auth provider for user: ${email}`);
      }

      this.logger.log(`✅ User validated: ${email}`);
      const { password: _, ...result } = user;
      return result;
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;
      throw new UnauthorizedException('Login failed');
    }
  }

  async register(registerDto: RegisterDto): Promise<AuthResponse> {
    try {
      const existingUser = await this.usersService.findByEmail(
        registerDto.email,
      );
      if (existingUser) throw new ConflictException('User already exists');

      if (registerDto.password.length < 8) {
        throw new BadRequestException(
          'Password must be at least 8 characters long',
        );
      }

      const hashedPassword = await bcrypt.hash(registerDto.password, 12);
      const emailVerificationToken = await this.generateEmailVerificationToken(
        registerDto.email.toLowerCase().trim(),
      );

      const user = await this.usersService.create({
        email: registerDto.email.toLowerCase().trim(),
        name: registerDto.name.trim(),
        password: hashedPassword,
        avatar: registerDto.avatar?.trim() || null,
        provider: 'local',
        isEmailVerified: false,
        verificationToken: emailVerificationToken,
      });

      // Create LOCAL auth provider for the user
      await this.prisma.authProvider.create({
        data: {
          userId: user.id,
          provider: this.mapStringToProviderEnum('local'),
          providerId: user.email, // Use email as providerId for local auth
          email: user.email,
          isPrimary: true, // Set as primary for local registration
        },
      });

      this.sendVerificationEmailAsync(user.email, emailVerificationToken);
      const tokens = await this.generateTokens(user.id, user.email, user.roles);

      // Get user with auth providers
      const userWithProviders = await this.prisma.user.findUnique({
        where: { id: user.id },
        include: {
          authProviders: {
            select: {
              provider: true,
              isPrimary: true,
              linkedAt: true,
            },
          },
        },
      });

      const { ...userResult } = userWithProviders;
      const primaryProvider =
        userResult.authProviders?.find((p) => p.isPrimary)?.provider || 'local';

      return {
        user: {
          id: userResult.id,
          email: userResult.email,
          name: userResult.name,
          avatar: userResult.avatar,
          provider: primaryProvider,
          isEmailVerified: userResult.isEmailVerified,
          isTwoFactorEnabled: userResult.isTwoFactorEnabled,
        },
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    } catch (error) {
      if (
        error instanceof ConflictException ||
        error instanceof BadRequestException
      )
        throw error;
      throw new InternalServerErrorException('Registration failed');
    }
  }

  async login(
    user: any,
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<AuthResponse | TwoFactorRequiredResponse> {
    if (user.isTwoFactorEnabled) {
      const tempToken = await this.jwtService.signAsync(
        { sub: user.id, email: user.email },
        {
          secret: this.configService.get('JWT_SECRET'),
          expiresIn: '15m',
        },
      );
      return {
        requiresTwoFactor: true,
        userId: user.id,
        email: user.email,
        tempToken,
      };
    }

    const tokens = await this.generateTokens(
      user.id,
      user.email,
      user.roles,
      rememberMe,
      ipAddress,
      userAgent,
    );
    const { password, verificationToken, twoFactorSecret, ...userResult } =
      user;

    // Get primary provider
    const primaryProvider = await this.prisma.authProvider.findFirst({
      where: { userId: user.id, isPrimary: true },
      select: { provider: true },
    });

    return {
      user: {
        id: userResult.id,
        email: userResult.email,
        name: userResult.name,
        avatar: userResult.avatar,
        provider: primaryProvider?.provider || 'local',
        isEmailVerified: userResult.isEmailVerified,
        isTwoFactorEnabled: userResult.isTwoFactorEnabled,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async loginWithTwoFactor(
    dto: LoginWithTwoFactorDto,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<AuthResponse> {
    try {
      const { tempToken, totpCode, rememberMe = false } = dto;

      let payload: JwtPayload;
      try {
        payload = await this.jwtService.verifyAsync(tempToken, {
          secret: this.configService.get('JWT_SECRET'),
        });
      } catch (err) {
        throw new UnauthorizedException('Invalid or expired temporary token');
      }

      const user = await this.usersService.findById(payload.sub);
      if (!user || !user.isTwoFactorEnabled) {
        throw new BadRequestException('2FA not enabled for this account');
      }

      const isValidCode = await this.verifyTwoFactorCode(user.id, totpCode);
      if (!isValidCode) {
        throw new UnauthorizedException('Invalid 2FA code');
      }

      const tokens = await this.generateTokens(
        user.id,
        user.email,
        user.roles,
        rememberMe,
        ipAddress,
        userAgent,
      );
      const { password, verificationToken, twoFactorSecret, ...userResult } =
        user;

      // Get primary provider
      const primaryProvider = await this.prisma.authProvider.findFirst({
        where: { userId: user.id, isPrimary: true },
        select: { provider: true },
      });

      // Log successful login
      await this.logAccessEvent(
        user.id,
        'LOGIN_SUCCESS',
        tokens.session.sessionId,
        ipAddress,
        userAgent,
      );

      return {
        user: {
          id: userResult.id,
          email: userResult.email,
          name: userResult.name,
          avatar: userResult.avatar,
          provider: primaryProvider?.provider || 'local',
          isEmailVerified: userResult.isEmailVerified,
          isTwoFactorEnabled: userResult.isTwoFactorEnabled,
        },
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException
      )
        throw error;
      throw new InternalServerErrorException('Login failed');
    }
  }

  // ===== SESSION MANAGEMENT METHODS =====

  /**

  /**
   * Stores a refresh token hashed in the database
   */
  async storeRefreshToken(
    sessionId: string,
    refreshToken: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<RefreshToken> {
    try {
      // Generate token hash for secure storage
      const tokenHash = await bcrypt.hash(refreshToken, 12);

      // Generate unique token family for rotation
      const tokenFamily = require('crypto').randomBytes(16).toString('hex');

      // Calculate token expiry
      const rememberMeSession = await this.prisma.userSession.findUnique({
        where: { id: sessionId },
        select: { rememberMe: true },
      });
      const tokenExpiryHours = rememberMeSession?.rememberMe ? 30 * 24 : 7 * 24; // 30 days or 7 days
      const expiresAt = new Date(
        Date.now() + tokenExpiryHours * 60 * 60 * 1000,
      );

      const refreshTokenRecord = await this.prisma.refreshToken.create({
        data: {
          sessionId,
          tokenHash,
          tokenFamily,
          ipAddress,
          userAgent,
          expiresAt,
        },
      });

      this.logger.log(`✅ Stored refresh token for session ${sessionId}`);
      return refreshTokenRecord;
    } catch (error) {
      this.logger.error(
        `Failed to store refresh token for session ${sessionId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Validates a refresh token against stored hashes and updates session activity
   */
  async validateAndConsumeRefreshToken(
    refreshToken: string,
    userId: string,
  ): Promise<{ session: UserSession; tokenFamily: string | null }> {
    try {
      // Find active user sessions for this user
      const activeSessions = await this.prisma.userSession.findMany({
        where: {
          userId,
          isActive: true,
          expiresAt: { gt: new Date() },
        },
        include: {
          refreshTokens: {
            where: { isActive: true },
          },
        },
      });

      if (activeSessions.length === 0) {
        throw new UnauthorizedException('No active sessions found');
      }

      // Check each session for a matching refresh token
      for (const session of activeSessions) {
        for (const tokenRecord of session.refreshTokens) {
          const isValidToken = await bcrypt.compare(
            refreshToken,
            tokenRecord.tokenHash,
          );

          if (isValidToken) {
            // Token is valid - mark it as used and update session
            await this.prisma.refreshToken.update({
              where: { id: tokenRecord.id },
              data: {
                isActive: false, // Consume the token (single use)
                usedAt: new Date(),
              },
            });

            // Update session activity
            await this.prisma.userSession.update({
              where: { id: session.id },
              data: { lastActivity: new Date() },
            });

            this.logger.log(
              `✅ Consumed valid refresh token for session ${session.id}`,
            );
            return { session, tokenFamily: tokenRecord.tokenFamily };
          }
        }
      }

      throw new UnauthorizedException('Invalid refresh token');
    } catch (error) {
      this.logger.error(
        `Refresh token validation failed for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Updates session activity timestamp
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
   * Logout user by deleting the current session and its refresh tokens
   */
  async logout(userId: string, currentSessionId?: string): Promise<void> {
    try {
      let sessionToDelete;

      if (currentSessionId) {
        // Find the specific session by sessionId
        sessionToDelete = await this.prisma.userSession.findFirst({
          where: {
            userId,
            sessionId: currentSessionId,
            isActive: true,
          },
          select: {
            id: true,
            sessionId: true,
          },
        });

        if (!sessionToDelete) {
          this.logger.warn(
            `Current session ${currentSessionId} not found or already inactive for user: ${userId}`,
          );
          return;
        }
      } else {
        // Fallback: find the most recent active session for the user
        sessionToDelete = await this.prisma.userSession.findFirst({
          where: {
            userId,
            isActive: true,
          },
          orderBy: {
            lastActivity: 'desc',
          },
          select: {
            id: true,
            sessionId: true,
          },
        });

        if (!sessionToDelete) {
          this.logger.log(`No active sessions found for user: ${userId}`);
          return;
        }
      }

      // Delete all refresh tokens for this session
      await this.prisma.refreshToken.deleteMany({
        where: {
          sessionId: sessionToDelete.id,
        },
      });

      // Delete the session
      await this.prisma.userSession.delete({
        where: {
          id: sessionToDelete.id,
        },
      });

      this.logger.log(
        `✅ Logged out user ${userId}: Session ${sessionToDelete.sessionId} and associated tokens deleted`,
      );
    } catch (error) {
      this.logger.error(`Failed to logout user ${userId}:`, error.message);
      throw error;
    }
  }

  async refreshToken(
    refreshToken: string,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<AuthResponse> {
    try {
      // Find the user
      const user = await this.usersService.findById(userId);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Validate and consume the refresh token
      const { session, tokenFamily } =
        await this.validateAndConsumeRefreshToken(refreshToken, userId);
      const rememberMe = session.rememberMe;

      // Update session activity
      await this.updateSessionActivity(session.id);

      // Generate new tokens with rotation
      const tokens = await this.generateTokens(
        userId,
        user.email,
        user.roles,
        rememberMe,
        ipAddress,
        userAgent,
      );

      const { password, verificationToken, twoFactorSecret, ...userResult } =
        user;

      // Get primary provider
      const primaryProvider = await this.prisma.authProvider.findFirst({
        where: { userId: user.id, isPrimary: true },
        select: { provider: true },
      });

      return {
        user: {
          id: userResult.id,
          email: userResult.email,
          name: userResult.name,
          avatar: userResult.avatar || null,
          provider: primaryProvider?.provider || 'local',
          isEmailVerified: userResult.isEmailVerified,
          isTwoFactorEnabled: userResult.isTwoFactorEnabled,
        },
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    } catch (error) {
      this.logger.error('Refresh token failed', error.message);
      if (error instanceof UnauthorizedException) throw error;
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  // ===== DEVICE FINGERPRINTING AND SECURITY METHODS =====

  /**
   * Generate a browser fingerprint hash from User-Agent and other headers
   */
  private generateBrowserFingerprintHash(
    userAgent: string,
    additionalHeaders?: Record<string, string>,
  ): string {
    try {
      const crypto = require('crypto');

      // Create fingerprint from User-Agent and additional headers
      const fingerprintData = {
        userAgent: userAgent || '',
        acceptLanguage: additionalHeaders?.['accept-language'] || '',
        acceptEncoding: additionalHeaders?.['accept-encoding'] || '',
        accept: additionalHeaders?.['accept'] || '',
        dnt: additionalHeaders?.['dnt'] || '',
        secChUa: additionalHeaders?.['sec-ch-ua'] || '',
        secChUaMobile: additionalHeaders?.['sec-ch-ua-mobile'] || '',
        secChUaPlatform: additionalHeaders?.['sec-ch-ua-platform'] || '',
      };

      // Create a stable hash from the fingerprint data
      const fingerprintString = JSON.stringify(
        fingerprintData,
        Object.keys(fingerprintData).sort(),
      );
      return crypto
        .createHash('sha256')
        .update(fingerprintString)
        .digest('hex');
    } catch (error) {
      this.logger.warn(
        'Failed to generate browser fingerprint hash:',
        error.message,
      );
      return '';
    }
  }

  /**
   * Detect geolocation from IP address (simplified implementation)
   */
  private async detectGeolocation(ipAddress: string): Promise<{
    latitude?: number;
    longitude?: number;
    timezone?: string;
    location?: string;
  }> {
    try {
      // For this implementation, we'll use a simple IP-based geolocation
      // In production, you'd use a service like MaxMind GeoIP or ip-api.com

      // Skip geolocation for private/local IPs
      if (this.isPrivateIP(ipAddress)) {
        return { location: 'Local Network' };
      }

      // Simple timezone detection based on IP (this is very basic)
      // In production, use a proper geolocation service
      const timezone = this.guessTimezoneFromIP(ipAddress);

      return {
        timezone,
        location: this.getLocationFromTimezone(timezone),
      };
    } catch (error) {
      this.logger.warn(
        `Failed to detect geolocation for IP ${ipAddress}:`,
        error.message,
      );
      return {};
    }
  }

  /**
   * Check if IP is private/local
   */
  private isPrivateIP(ip: string): boolean {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^::1$/,
      /^fc00:/,
      /^fe80:/,
    ];
    return privateRanges.some((range) => range.test(ip));
  }

  /**
   * Guess timezone from IP (very basic implementation)
   */
  private guessTimezoneFromIP(ip: string): string {
    // This is a very basic implementation
    // In production, use a proper geolocation service

    // Default to UTC
    if (!ip || ip === 'unknown' || ip === '::1') {
      return 'UTC';
    }

    // For demonstration, we'll use a simple mapping
    // This should be replaced with actual geolocation service
    return 'Asia/Dhaka'; // Default for this example
  }

  /**
   * Get location string from timezone
   */
  private getLocationFromTimezone(timezone: string): string {
    const locationMap: Record<string, string> = {
      UTC: 'Unknown',
      'America/New_York': 'New York, US',
      'America/Los_Angeles': 'Los Angeles, US',
      'Europe/London': 'London, UK',
      'Europe/Paris': 'Paris, France',
      'Asia/Tokyo': 'Tokyo, Japan',
      'Asia/Shanghai': 'Shanghai, China',
      'Asia/Dhaka': 'Dhaka, Bangladesh',
      'Australia/Sydney': 'Sydney, Australia',
    };

    return locationMap[timezone] || timezone;
  }

  /**
   * Detect suspicious activity based on session patterns
   */
  private async detectSuspiciousActivity(
    userId: string,
    currentSession: any,
    newIpAddress?: string,
    newUserAgent?: string,
    newDeviceFingerprint?: string,
  ): Promise<{
    isSuspicious: boolean;
    riskScore: number;
    reasons: string[];
  }> {
    const reasons: string[] = [];
    let riskScore = 0;

    try {
      // Get recent sessions for this user
      const recentSessions = await this.prisma.userSession.findMany({
        where: {
          userId,
          createdAt: {
            gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
          },
        },
        select: {
          ipAddress: true,
          userAgent: true,
          browserFingerprintHash: true,
          location: true,
          createdAt: true,
          deviceFingerprintConfidence: true,
          latitude: true,
          longitude: true,
          timezone: true,
          riskScore: true,
          unusualActivityCount: true,
        },
        orderBy: {
          createdAt: 'desc',
        },
        take: 10, // Last 10 sessions
      });

      // Check for IP address changes
      if (newIpAddress && !this.isPrivateIP(newIpAddress)) {
        const uniqueIPs = new Set(
          recentSessions.map((s) => s.ipAddress).filter(Boolean),
        );
        if (uniqueIPs.size > 0 && !uniqueIPs.has(newIpAddress)) {
          riskScore += 0.3; // Moderate risk for new IP
          reasons.push('New IP address detected');

          // Log IP change
          this.loggerService.security(
            'IP_ADDRESS_CHANGED',
            {
              previousIPs: Array.from(uniqueIPs),
              newIP: newIpAddress,
            },
            userId,
            newIpAddress,
          );
        }
      }

      // Check for device fingerprint changes
      if (newDeviceFingerprint) {
        const uniqueFingerprints = new Set(
          recentSessions.map((s) => s.browserFingerprintHash).filter(Boolean),
        );
        if (
          uniqueFingerprints.size > 0 &&
          !uniqueFingerprints.has(newDeviceFingerprint)
        ) {
          riskScore += 0.4; // Higher risk for new device
          reasons.push('New device fingerprint detected');

          // Log device change
          this.loggerService.security(
            'DEVICE_FINGERPRINT_CHANGED',
            {
              previousFingerprints: Array.from(uniqueFingerprints),
              newFingerprint: newDeviceFingerprint,
            },
            userId,
            newIpAddress,
          );
        }
      }

      // Check for unusual access patterns
      const recentHour = new Date(Date.now() - 60 * 60 * 1000);
      const sessionsLastHour = recentSessions.filter(
        (s) => s.createdAt > recentHour,
      );

      if (sessionsLastHour.length > 5) {
        riskScore += 0.5; // High risk for frequent access
        reasons.push('Unusual access frequency detected');

        this.loggerService.security(
          'UNUSUAL_ACCESS_PATTERN',
          {
            sessionsInLastHour: sessionsLastHour.length,
          },
          userId,
          newIpAddress,
        );
      }

      // Check for geographic changes
      if (newIpAddress) {
        const newLocation = await this.detectGeolocation(newIpAddress);
        const recentLocations = recentSessions
          .map((s) => s.location)
          .filter(Boolean)
          .filter((loc, idx, arr) => arr.indexOf(loc) === idx); // Unique locations

        if (
          recentLocations.length > 0 &&
          newLocation.location &&
          !recentLocations.includes(newLocation.location)
        ) {
          riskScore += 0.2; // Low-moderate risk for new location
          reasons.push('New geographic location detected');

          this.loggerService.security(
            'GEOLOCATION_CHANGED',
            {
              previousLocations: recentLocations,
              newLocation: newLocation.location,
            },
            userId,
            newIpAddress,
          );
        }
      }

      // Check session concurrency limits
      const configMaxSessions = this.configService.get<number>(
        'MAX_CONCURRENT_SESSIONS',
        5,
      );
      const activeSessions = await this.prisma.userSession.count({
        where: {
          userId,
          isActive: true,
          expiresAt: { gt: new Date() },
        },
      });

      if (activeSessions >= configMaxSessions) {
        riskScore += 0.8; // Very high risk - session limit exceeded
        reasons.push(
          `Session concurrency limit exceeded (${activeSessions}/${configMaxSessions})`,
        );

        this.loggerService.security(
          'SESSION_CONCURRENCY_LIMIT_EXCEEDED',
          {
            activeSessions,
            maxAllowed: configMaxSessions,
          },
          userId,
          newIpAddress,
        );
      }

      // Increase risk score based on unusual activity count
      if (currentSession?.unusualActivityCount > 0) {
        riskScore += Math.min(currentSession.unusualActivityCount * 0.1, 0.5);
        reasons.push(
          `${currentSession.unusualActivityCount} unusual activities detected`,
        );
      }

      // Cap risk score at 1.0
      riskScore = Math.min(riskScore, 1.0);

      const isSuspicious = riskScore >= 0.7; // Threshold for suspicious activity

      if (isSuspicious) {
        this.loggerService.security(
          'SUSPICIOUS_ACTIVITY_DETECTED',
          {
            riskScore,
            reasons,
          },
          userId,
          newIpAddress,
        );

        this.loggerService.suspiciousActivity(
          'Multiple suspicious patterns detected',
          {
            riskScore,
            reasons,
          },
          newIpAddress,
        );
      }

      return { isSuspicious, riskScore, reasons };
    } catch (error) {
      this.logger.warn(
        `Failed to detect suspicious activity for user ${userId}:`,
        error.message,
      );
      return { isSuspicious: false, riskScore: 0, reasons: [] };
    }
  }

  /**
   * Enhanced session creation with device fingerprinting and security checks
   */
  async createUserSession(
    userId: string,
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
    deviceInfo?: any,
    additionalHeaders?: Record<string, string>,
  ): Promise<UserSession> {
    try {
      // Enforce session concurrency limits before creating new session
      await this.enforceSessionConcurrencyLimit(userId);

      // Generate device fingerprint
      const browserFingerprintHash = this.generateBrowserFingerprintHash(
        userAgent || '',
        additionalHeaders,
      );

      // Detect geolocation
      const geolocation = ipAddress
        ? await this.detectGeolocation(ipAddress)
        : {};

      // Calculate session expiry
      const sessionExpiryHours = rememberMe ? 30 * 24 : 24; // 30 days or 24 hours
      const expiresAt = new Date(
        Date.now() + sessionExpiryHours * 60 * 60 * 1000,
      );

      // Generate unique session ID
      const sessionId = require('crypto').randomBytes(32).toString('hex');

      // Create enhanced session data
      const sessionData = {
        userId,
        sessionId,
        deviceInfo: {
          ...deviceInfo,
          fingerprintGeneratedAt: new Date().toISOString(),
        },
        ipAddress,
        userAgent,
        location: geolocation.location,
        browserFingerprintHash,
        deviceFingerprintConfidence: 0.8, // Default confidence for basic implementation
        latitude: geolocation.latitude,
        longitude: geolocation.longitude,
        timezone: geolocation.timezone,
        rememberMe,
        expiresAt,
      };

      const session = await this.prisma.userSession.create({
        data: sessionData,
      });

      // Log device fingerprint capture
      if (browserFingerprintHash) {
        this.loggerService.security(
          'DEVICE_FINGERPRINT_CAPTURED',
          {
            fingerprintHash: browserFingerprintHash.substring(0, 8) + '...', // Partial hash for logging
            confidence: sessionData.deviceFingerprintConfidence,
            location: geolocation.location,
          },
          userId,
          ipAddress,
        );
      }

      this.logger.log(
        `✅ Created enhanced session ${sessionId} for user ${userId}`,
      );
      this.loggerService.security(
        'SESSION_ACTIVITY_MONITORED',
        {
          sessionId,
          fingerprintHash: browserFingerprintHash
            ? browserFingerprintHash.substring(0, 8) + '...'
            : null,
          location: geolocation.location,
        },
        userId,
        ipAddress,
      );

      return session;
    } catch (error) {
      this.logger.error(
        `Failed to create enhanced user session for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Enforce session concurrency limits
   */
  private async enforceSessionConcurrencyLimit(userId: string): Promise<void> {
    try {
      const configMaxSessions = this.configService.get<number>(
        'MAX_CONCURRENT_SESSIONS',
        5,
      );

      // Count active sessions for this user
      const activeSessionCount = await this.prisma.userSession.count({
        where: {
          userId,
          isActive: true,
          expiresAt: { gt: new Date() },
        },
      });

      // If limit exceeded, invalidate oldest sessions
      if (activeSessionCount >= configMaxSessions) {
        const sessionsToInvalidate = await this.prisma.userSession.findMany({
          where: {
            userId,
            isActive: true,
            expiresAt: { gt: new Date() },
          },
          select: {
            id: true,
            sessionId: true,
            createdAt: true,
          },
          orderBy: {
            lastActivity: 'asc', // Oldest first
          },
          take: activeSessionCount - configMaxSessions + 1, // Remove enough to stay under limit
        });

        if (sessionsToInvalidate.length > 0) {
          // Mark sessions as inactive
          await this.prisma.userSession.updateMany({
            where: {
              id: { in: sessionsToInvalidate.map((s) => s.id) },
            },
            data: {
              isActive: false,
              invalidatedAt: new Date(),
              invalidationReason: 'CONCURRENCY_LIMIT_EXCEEDED',
            },
          });

          // Log the invalidation
          for (const session of sessionsToInvalidate) {
            this.loggerService.security(
              'SESSION_INVALIDATED',
              {
                reason: 'CONCURRENCY_LIMIT_EXCEEDED',
                maxAllowed: configMaxSessions,
                activeCount: activeSessionCount,
              },
              userId,
            );

            await this.logAccessEvent(
              userId,
              'SESSION_INVALIDATED',
              session.sessionId,
            );
          }

          this.logger.log(
            `Enforced concurrency limit: Invalidated ${sessionsToInvalidate.length} sessions for user ${userId}`,
          );
        }
      }
    } catch (error) {
      this.logger.warn(
        `Failed to enforce session concurrency limit for user ${userId}:`,
        error.message,
      );
      // Don't throw error - allow session creation to continue
    }
  }

  /**
   * Enhanced session invalidation with suspicious activity detection
   */
  async invalidateSessionOnSuspiciousActivity(
    userId: string,
    sessionId: string,
    reason: string,
  ): Promise<void> {
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

      // Update session with invalidation details
      await this.prisma.userSession.update({
        where: { id: session.id },
        data: {
          isActive: false,
          invalidatedAt: new Date(),
          invalidationReason: reason,
          riskScore: Math.min((session.riskScore || 0) + 0.5, 1.0), // Increase risk score
        },
      });

      // Delete all refresh tokens for this session
      await this.prisma.refreshToken.deleteMany({
        where: {
          sessionId: session.id,
        },
      });

      // Log security event
      this.loggerService.security(
        'SESSION_INVALIDATED',
        {
          reason,
          sessionId,
          invalidationTime: new Date().toISOString(),
        },
        userId,
      );

      await this.logAccessEvent(
        userId,
        'SESSION_INVALIDATED',
        session.sessionId,
      );

      this.logger.log(
        `Session ${sessionId} invalidated due to suspicious activity: ${reason}`,
      );
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      this.logger.error(
        `Failed to invalidate session ${sessionId}:`,
        error.message,
      );
      throw error;
    }
  }

  // ===== USER NOTIFICATION SYSTEM =====

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

  async generateTokens(
    userId: string,
    email: string,
    roles: string[],
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
    deviceInfo?: any,
    additionalHeaders?: Record<string, string>,
  ): Promise<RefreshTokenResponse> {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      const refreshSecret =
        this.configService.get<string>('JWT_REFRESH_SECRET');
      if (!jwtSecret || !refreshSecret) throw new Error('JWT secrets missing');

      // Generate session expiry and refresh token expiry
      const sessionExpiryHours = rememberMe ? 30 * 24 : 24; // 30 days or 24 hours
      const refreshTokenExpiryHours = rememberMe ? 30 * 24 : 7 * 24; // 30 days or 7 days

      // Create user session with enhanced security
      const session = await this.createUserSession(
        userId,
        rememberMe,
        ipAddress,
        userAgent,
        deviceInfo,
        additionalHeaders,
      );

      // Create base payload
      const payload: JwtPayload = {
        sub: userId,
        email,
        roles,
        rememberMe,
        sessionId: session.sessionId, // Include session ID in token
        tokenFamily: require('crypto').randomBytes(16).toString('hex'), // New token family
      };

      const accessTokenExpiresIn =
        this.configService.get<string>('JWT_EXPIRES_IN') || '15m';
      const refreshTokenExpiresIn = rememberMe
        ? this.configService.get<string>(
            'JWT_REFRESH_REMEMBER_ME_EXPIRES_IN',
          ) || '30d'
        : this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || '7d';

      // Generate access token
      const accessToken = await this.jwtService.signAsync(payload, {
        secret: jwtSecret,
        expiresIn: accessTokenExpiresIn,
      });

      // Generate refresh token with session info
      const refreshPayload: JwtPayload = {
        sub: userId,
        email,
        roles,
        rememberMe,
        sessionId: session.sessionId,
        tokenFamily: payload.tokenFamily,
      };

      const refreshToken = await this.jwtService.signAsync(refreshPayload, {
        secret: refreshSecret,
        expiresIn: refreshTokenExpiresIn,
      });

      // Store refresh token in database
      await this.storeRefreshToken(
        session.id,
        refreshToken,
        ipAddress,
        userAgent,
      );

      this.logger.log(`✅ Generated tokens for session ${session.sessionId}`);
      return { accessToken, refreshToken, session };
    } catch (error) {
      this.logger.error(
        `Failed to generate tokens for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  async loginWithBackupCode(
    tempToken: string,
    backupCode: string,
    rememberMe: boolean = false,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<AuthResponse> {
    try {
      let payload: JwtPayload;
      try {
        payload = await this.jwtService.verifyAsync(tempToken, {
          secret: this.configService.get('JWT_SECRET'),
        });
      } catch (err) {
        this.logger.warn(
          'Invalid or expired temporary token for backup code login',
        );
        throw new UnauthorizedException('Invalid or expired temporary token');
      }

      const user = await this.usersService.findById(payload.sub);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      if (!user.isTwoFactorEnabled || !user.backupCodes?.length) {
        this.logger.warn(
          `Backup code attempt for user without 2FA: ${user.email}`,
        );
        throw new UnauthorizedException(
          'Two-factor authentication is not enabled for this account',
        );
      }

      const normalizedBackupCode = backupCode.toUpperCase().replace(/\s/g, '');

      if (!/^[A-Z0-9]{8}$/.test(normalizedBackupCode)) {
        this.logger.warn(`Invalid backup code format for user: ${user.email}`);
        throw new UnauthorizedException(
          'Backup code must be exactly 8 uppercase alphanumeric characters',
        );
      }

      let matched = false;
      let validHash: string | null = null;

      for (const hash of user.backupCodes) {
        if (await bcrypt.compare(normalizedBackupCode, hash)) {
          matched = true;
          validHash = hash;
          break;
        }
      }

      if (!matched) {
        this.logger.warn(
          `❌ Failed backup code attempt for user: ${user.email}`,
        );
        this.logger.debug(
          `Total backup codes in DB: ${user.backupCodes.length}`,
        );
        this.logger.debug(
          `Input backup code: ${normalizedBackupCode} (length: ${normalizedBackupCode.length})`,
        );
        throw new UnauthorizedException('Invalid backup code');
      }

      const remainingBackupCodes = user.backupCodes.filter(
        (h) => h !== validHash,
      );

      await this.usersService.update(user.id, {
        backupCodes: { set: remainingBackupCodes },
      });

      this.logger.log(
        `✅ Backup code used successfully for user: ${user.email}. Remaining codes: ${remainingBackupCodes.length}`,
      );

      const tokens = await this.generateTokens(
        user.id,
        user.email,
        user.roles,
        rememberMe,
        ipAddress,
        userAgent,
      );

      const { password, verificationToken, twoFactorSecret, ...userResult } =
        user;

      // Get primary provider
      const primaryProvider = await this.prisma.authProvider.findFirst({
        where: { userId: user.id, isPrimary: true },
        select: { provider: true },
      });

      return {
        user: {
          id: userResult.id,
          email: userResult.email,
          name: userResult.name,
          avatar: userResult.avatar,
          provider: primaryProvider?.provider || 'local',
          isEmailVerified: userResult.isEmailVerified,
          isTwoFactorEnabled: userResult.isTwoFactorEnabled,
        },
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;
      this.logger.error(
        `Backup code login failed: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Backup code login failed');
    }
  }

  async validateOAuthUser(oauthUser: {
    email: string;
    name: string;
    avatar?: string;
    provider: string;
    providerId: string;
    accessToken?: string;
    refreshToken?: string;
    tokenExpiresAt?: Date;
    providerData?: any;
  }) {
    try {
      const providerEnum = this.mapStringToProviderEnum(oauthUser.provider);

      // Find existing user by email
      let existingUser = await this.usersService.findByEmail(
        oauthUser.email.toLowerCase().trim(),
      );

      if (!existingUser) {
        // Create new user if they don't exist
        existingUser = await this.usersService.create({
          email: oauthUser.email.toLowerCase().trim(),
          name: oauthUser.name.trim(),
          avatar: oauthUser.avatar,
          provider: oauthUser.provider, // Keep for backward compatibility
          isEmailVerified: true,
          emailVerifiedAt: new Date(),
          verificationToken: null,
        });
      } else if (!existingUser.isEmailVerified) {
        await this.usersService.markEmailAsVerified(existingUser.id);
      }

      // Check if this provider is already linked to the user
      const existingProvider = await this.prisma.authProvider.findUnique({
        where: {
          userId_provider: {
            userId: existingUser.id,
            provider: providerEnum,
          },
        },
      });

      if (!existingProvider) {
        // Link the new provider to the user
        await this.prisma.authProvider.create({
          data: {
            userId: existingUser.id,
            provider: providerEnum,
            providerId: oauthUser.providerId,
            email: oauthUser.email,
            accessToken: oauthUser.accessToken,
            refreshToken: oauthUser.refreshToken,
            tokenExpiresAt: oauthUser.tokenExpiresAt,
            providerData: oauthUser.providerData || {},
            isPrimary: false, // Will be set to true if this is the first provider
          },
        });

        // If user has no primary provider, make this one primary
        const primaryProviderCount = await this.prisma.authProvider.count({
          where: { userId: existingUser.id, isPrimary: true },
        });

        if (primaryProviderCount === 0) {
          await this.setPrimaryProvider(existingUser.id, providerEnum);
        }
      } else {
        // Update existing provider data
        await this.prisma.authProvider.update({
          where: { id: existingProvider.id },
          data: {
            accessToken: oauthUser.accessToken,
            refreshToken: oauthUser.refreshToken,
            tokenExpiresAt: oauthUser.tokenExpiresAt,
            providerData:
              oauthUser.providerData || existingProvider.providerData,
            lastUsedAt: new Date(),
          },
        });
      }

      return existingUser;
    } catch (error) {
      this.logger.error('OAuth user validation failed:', error.message);
      throw new InternalServerErrorException('OAuth authentication failed');
    }
  }

  private mapStringToProviderEnum(provider: string): any {
    const providerMap: { [key: string]: any } = {
      local: 'LOCAL',
      google: 'GOOGLE',
      facebook: 'FACEBOOK',
      github: 'GITHUB',
      twitter: 'TWITTER',
      linkedin: 'LINKEDIN',
      microsoft: 'MICROSOFT',
      apple: 'APPLE',
    };

    const enumValue = providerMap[provider.toLowerCase()];
    if (!enumValue) {
      throw new Error(`Unsupported provider: ${provider}`);
    }

    return enumValue;
  }

  async setPrimaryProvider(userId: string, provider: any): Promise<void> {
    // First, unset all primary flags for this user
    await this.prisma.authProvider.updateMany({
      where: { userId },
      data: { isPrimary: false },
    });

    // Set the specified provider as primary
    await this.prisma.authProvider.updateMany({
      where: { userId, provider },
      data: { isPrimary: true },
    });
  }

  async getUserProviders(userId: string): Promise<any[]> {
    return this.prisma.authProvider.findMany({
      where: { userId },
      select: {
        id: true,
        provider: true,
        email: true,
        isPrimary: true,
        linkedAt: true,
        lastUsedAt: true,
      },
      orderBy: { linkedAt: 'asc' },
    });
  }

  async unlinkProvider(userId: string, provider: string): Promise<void> {
    const providerEnum = this.mapStringToProviderEnum(provider);

    const providerRecord = await this.prisma.authProvider.findUnique({
      where: {
        userId_provider: {
          userId,
          provider: providerEnum,
        },
      },
    });

    if (!providerRecord) {
      throw new NotFoundException(
        `Provider ${provider} is not linked to this account`,
      );
    }

    // Don't allow unlinking if it's the only provider and user has no password
    const user = await this.usersService.findById(userId);
    if (!user?.password) {
      const providerCount = await this.prisma.authProvider.count({
        where: { userId },
      });

      if (providerCount <= 1) {
        throw new BadRequestException(
          'Cannot unlink the only authentication provider without a password set. Please set a password first.',
        );
      }
    }

    await this.prisma.authProvider.delete({
      where: { id: providerRecord.id },
    });

    // If the unlinked provider was primary, set another one as primary
    if (providerRecord.isPrimary) {
      const remainingProvider = await this.prisma.authProvider.findFirst({
        where: { userId },
        orderBy: { linkedAt: 'asc' },
      });

      if (remainingProvider) {
        await this.setPrimaryProvider(userId, remainingProvider.provider);
      }
    }
  }

  async googleLogin(user: any): Promise<AuthResponse> {
    const validatedUser = await this.validateOAuthUser({
      email: user.email,
      name: user.name,
      avatar: user.picture,
      provider: 'google',
      providerId: user.googleId || user.id,
      accessToken: user.accessToken,
      refreshToken: user.refreshToken,
      providerData: {
        profile: user,
      },
    });
    const result = await this.login(validatedUser);
    if ('requiresTwoFactor' in result) {
      throw new BadRequestException(
        '2FA required. Please complete setup first.',
      );
    }
    return result;
  }

  async facebookLogin(user: any): Promise<AuthResponse> {
    const validatedUser = await this.validateOAuthUser({
      email: user.email,
      name: user.name,
      avatar: user.picture,
      provider: 'facebook',
      providerId: user.facebookId || user.id,
      accessToken: user.accessToken,
      refreshToken: user.refreshToken,
      providerData: {
        profile: user,
      },
    });
    const result = await this.login(validatedUser);
    if ('requiresTwoFactor' in result) {
      throw new BadRequestException(
        '2FA required. Please complete setup first.',
      );
    }
    return result;
  }

  async githubLogin(user: any): Promise<AuthResponse> {
    const validatedUser = await this.validateOAuthUser({
      email: user.email,
      name: user.name,
      avatar: user.avatar,
      provider: 'github',
      providerId: user.githubId || user.id,
      accessToken: user.accessToken,
      refreshToken: user.refreshToken,
      providerData: {
        profile: user,
        username: user.username,
      },
    });
    const result = await this.login(validatedUser);
    if ('requiresTwoFactor' in result) {
      throw new BadRequestException(
        '2FA required. Please complete setup first.',
      );
    }
    return result;
  }

  private generateTOTPCode(secret: string, timeCounter: number): string {
    try {
      const crypto = require('crypto');
      const buffer = Buffer.allocUnsafe(8);
      buffer.writeUInt32BE(0, 0);
      buffer.writeUInt32BE(timeCounter, 4);

      const key = this.base32Decode(secret);
      const hmac = crypto.createHmac('sha1', key);
      hmac.update(buffer);
      const digest = hmac.digest();

      const offset = digest[digest.length - 1] & 0x0f;

      const code =
        ((digest[offset] & 0x7f) << 24) |
        ((digest[offset + 1] & 0xff) << 16) |
        ((digest[offset + 2] & 0xff) << 8) |
        (digest[offset + 3] & 0xff);

      const finalCode = (code % 1000000).toString().padStart(6, '0');
      this.logger.debug(`TOTP Code: ${finalCode} (time: ${timeCounter})`);

      return finalCode;
    } catch (error) {
      return totp.generate(secret);
    }
  }

  private base32Decode(encoded: string): Buffer {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0;
    let value = 0;
    let index = 0;
    const output = new Uint8Array((encoded.length * 5) >> 3);

    for (const char of encoded.toUpperCase()) {
      const idx = alphabet.indexOf(char);
      if (idx === -1) continue;

      value = (value << 5) | idx;
      bits += 5;

      if (bits >= 8) {
        output[index++] = (value >>> (bits - 8)) & 255;
        bits -= 8;
      }
    }

    return Buffer.from(output.slice(0, index));
  }

  /**
   * Enhanced OTP Auth URL generation with support for multiple algorithms and parameters
   */
  private generateEnhancedOtpAuthUrl(
    secret: string,
    issuer: string,
    accountName: string,
    options: {
      type?: 'TOTP' | 'HOTP';
      algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
      digits?: number;
      period?: number;
      counter?: number;
      image?: string;
    } = {},
  ): string {
    const {
      type = 'TOTP',
      algorithm = this.enhancedTotpConfig.algorithm,
      digits = this.enhancedTotpConfig.digits,
      period = this.enhancedTotpConfig.step,
      counter = 0,
      image,
    } = options;

    // Remove issuerUrl reference since it's not part of the standard otpauth URL specification
    // Build the label with proper encoding
    const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;

    // Build query parameters
    const params = new URLSearchParams();
    params.append('secret', secret);
    params.append('issuer', issuer);
    params.append('algorithm', algorithm);
    params.append('digits', digits.toString());

    // Add type-specific parameters
    if (type === 'TOTP') {
      params.append('period', period.toString());
    } else if (type === 'HOTP') {
      params.append('counter', counter.toString());
    }

    // Add optional parameters
    if (image) {
      params.append('image', encodeURIComponent(image));
    }

    // Build the full URL
    const baseUrl = `otpauth://${type.toLowerCase()}/${label}`;
    const queryString = params.toString();

    return `${baseUrl}?${queryString}`;
  }

  async generateTwoFactorSecret(
    userId: string,
  ): Promise<TwoFactorGenerateResponse> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) throw new BadRequestException('User not found');

      this.logger.log(`Generating 2FA secret for user: ${user.email}`);

      const secret = authenticator.generateSecret();
      const serviceName = this.appName.replace(/\s+/g, '');
      const issuer = this.appName;
      const accountName = `${user.email.split('@')[0]}@${user.email.split('@')[1]}`;

      // Enhanced OTP Auth URL generation with multiple improvements
      const otpAuthUrl = this.generateEnhancedOtpAuthUrl(
        secret,
        issuer,
        accountName,
        {
          type: 'TOTP',
          algorithm: this.enhancedTotpConfig.algorithm,
          digits: this.enhancedTotpConfig.digits,
          period: this.enhancedTotpConfig.step,
          // Add image parameter if user has avatar
          image: user.avatar ? encodeURIComponent(user.avatar) : undefined,
        },
      );

      // Handle QR code generation with proper error checking
      try {
        const qr = QRCode(0, 'L');
        qr.addData(otpAuthUrl);
        qr.make();
        const qrCodeUrl = qr.createDataURL(4);

        await this.usersService.update(userId, {
          twoFactorSecret: secret,
        });

        const result = {
          secret,
          qrCodeUrl,
          manualEntryKey: secret,
          otpAuthUrl,
        };

        this.logger.log(
          `✅ 2FA secret generated successfully for user: ${user.email}`,
        );
        return result;
      } catch (qrError) {
        this.logger.error(
          `Failed to generate QR code for user ${userId}:`,
          qrError.message,
        );
        throw new BadRequestException('Failed to generate QR code');
      }
    } catch (error) {
      if (error instanceof BadRequestException) throw error;
      this.logger.error(
        `Failed to generate 2FA secret for user ${userId}:`,
        error.message,
      );
      throw new BadRequestException('Failed to generate 2FA secret');
    }
  }

  async verifyTwoFactorCode(
    userId: string,
    totpCode: string,
  ): Promise<boolean> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user || !user.twoFactorSecret) {
        this.logger.warn(`No 2FA secret found for user: ${userId}`);
        return false;
      }

      const cleanCode = totpCode.replace(/\s/g, '').padStart(6, '0');

      if (!/^\d{6}$/.test(cleanCode)) {
        this.logger.warn(`Invalid code format: ${cleanCode}`);
        return false;
      }

      const secret = user.twoFactorSecret;
      const currentExpected = totp.generate(secret);
      this.logger.debug(`Current expected code: ${currentExpected}`);
      this.logger.debug(`Received code: ${cleanCode}`);

      // Manual window check with logging
      const currentTime = Math.floor(Date.now() / 1000);
      const timeStep = 30;
      const windowSize = 3;
      const isValid = totp.check(cleanCode, secret);

      if (isValid) {
        this.logger.log(`✅ 2FA code verified for user: ${user.email}`);
        return true;
      }

      // Log what codes would be valid in the current window
      this.logger.debug(`Checked time window: ±${windowSize * timeStep}s`);
      for (let i = -windowSize; i <= windowSize; i++) {
        const testTime = currentTime + i * timeStep;
        const testCounter = Math.floor(testTime / timeStep);
        const testCode = this.generateTOTPCode(secret, testCounter);
        this.logger.debug(
          `Expected code at offset ${i * timeStep}s: ${testCode} (time: ${new Date(testTime * 1000).toISOString()})`,
        );
        if (testCode === cleanCode) {
          this.logger.log(
            `✅ 2FA code verified for user: ${user.email} at offset ${i * 30}s`,
          );
          return true;
        }
      }

      const serverTime = new Date().toISOString();
      const serverTimestamp = Math.floor(Date.now() / 1000);

      this.logger.warn(`❌ No matching code found for user: ${user.email}`);
      this.logger.debug(`Received code: ${cleanCode}`);
      this.logger.debug(`Server time: ${serverTime} (${serverTimestamp})`);
      this.logger.debug(
        `Checked time window: ±${this.totpOptions.window * this.totpOptions.step}s`,
      );

      // Provide debugging info in the warning
      this.logger.warn(`⏰ Time sync debugging for user ${userId}:`);
      this.logger.warn(
        `📱 Ensure authenticator app is time-synced with NTP server`,
      );
      this.logger.warn(`🌍 Client timezone differences may cause this issue`);
      this.logger.warn(`⚙️ Check device time vs ${serverTime}`);

      return false;
    } catch (error) {
      this.logger.error(
        `Failed to verify 2FA code for user ${userId}:`,
        error.message,
      );
      return false;
    }
  }

  async enableTwoFactor(
    userId: string,
    totpCode: string,
  ): Promise<TwoFactorEnableResponse | void> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new BadRequestException('User not found');

    // If 2FA is already enabled, disable it first to allow re-enabling with new secret
    if (user.isTwoFactorEnabled) {
      this.logger.log(
        `🔄 Disabling existing 2FA for user: ${user.email} to allow re-enabling`,
      );
      await this.usersService.update(userId, {
        isTwoFactorEnabled: false,
        backupCodes: { set: [] }, // Clear existing backup codes
        // Keep the twoFactorSecret as it might be newly generated
      });
      this.logger.log(
        `✅ Existing 2FA disabled for re-enabling: ${user.email}`,
      );
    }

    if (!user.twoFactorSecret) {
      throw new BadRequestException(
        'No 2FA secret generated. Run /2fa/generate first.',
      );
    }

    const isValid = await this.verifyTwoFactorCode(userId, totpCode);
    if (!isValid) {
      const currentCode = totp.generate(user.twoFactorSecret);
      const timeInfo = `Current server time: ${new Date().toISOString()}`;

      this.logger.warn(
        `2FA enable failed for ${user.email}: Expected=${currentCode}, Received=${totpCode}`,
      );
      this.logger.warn(`Time sync issue? ${timeInfo}`);

      throw new UnauthorizedException(
        `Invalid verification code. Server expected: ${currentCode} (${timeInfo}). ` +
          'Please check your device time synchronization.',
      );
    }

    // Enable 2FA without generating backup codes
    await this.usersService.update(userId, {
      isTwoFactorEnabled: true,
    });

    this.logger.log(`✅ 2FA enabled for user: ${user.email}`);
  }

  async disableTwoFactor(userId: string, totpCode: string): Promise<void> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new BadRequestException('User not found');
    if (!user.isTwoFactorEnabled)
      throw new BadRequestException('2FA is not enabled');
    if (!user.twoFactorSecret) {
      throw new BadRequestException('2FA secret not found');
    }

    this.logger.log(`🔄 Disabling 2FA for user: ${user.email}`);
    this.logger.log(
      `📋 Current state - enabled: ${user.isTwoFactorEnabled}, secret: ${!!user.twoFactorSecret}, backupCodes: ${user.backupCodes?.length || 0}`,
    );

    const isValid = await this.verifyTwoFactorCode(userId, totpCode);
    if (!isValid) {
      const expectedCode = totp.generate(user.twoFactorSecret);
      this.logger.debug(
        `Expected code during disable: ${expectedCode}, Received: ${totpCode}`,
      );
      throw new UnauthorizedException(
        `Invalid verification code. Did you mean ${expectedCode}? Check device time.`,
      );
    }

    await this.usersService.update(userId, {
      isTwoFactorEnabled: false,
      twoFactorSecret: null,
      backupCodes: { set: [] },
    });

    this.logger.log(
      `🗑️ 2FA cleanup completed: secret cleared, backup codes emptied`,
    );
    this.logger.log(`✅ 2FA disabled for user: ${user.email}`);

    // Double-check the cleanup was successful
    const updatedUser = await this.usersService.findById(userId);
    if (updatedUser?.twoFactorSecret || updatedUser?.backupCodes?.length) {
      this.logger.warn(`⚠️ 2FA cleanup incomplete for user ${user.email}`);
    } else {
      this.logger.log(`🛡️ 2FA fully disabled for user: ${user.email}`);
    }
  }

  async regenerateBackupCodes(
    userId: string,
    dto: RegenerateBackupCodesDto,
  ): Promise<TwoFactorEnableResponse> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) {
        throw new BadRequestException('User not found');
      }

      if (!user.isTwoFactorEnabled) {
        throw new BadRequestException(
          'Two-factor authentication is not enabled for this account',
        );
      }

      if (!user.twoFactorSecret) {
        throw new BadRequestException('2FA secret not found');
      }

      // Verify the provided TOTP code
      const isValid = await this.verifyTwoFactorCode(userId, dto.totpCode);
      if (!isValid) {
        const currentCode = totp.generate(user.twoFactorSecret);
        this.logger.warn(
          `2FA regeneration failed for ${user.email}: Expected=${currentCode}, Received=${dto.totpCode}`,
        );
        throw new UnauthorizedException(
          `Invalid verification code. Please verify your device time and try again.`,
        );
      }

      // Generate new backup codes
      const newBackupCodes = Array.from({ length: 10 }, () =>
        Math.random().toString(36).slice(2, 10).toUpperCase(),
      );

      // Hash the new backup codes
      const hashedBackupCodes = await Promise.all(
        newBackupCodes.map((code) => bcrypt.hash(code, 12)),
      );

      // Update user with new hashed backup codes
      await this.usersService.update(userId, {
        backupCodes: {
          set: hashedBackupCodes,
        },
      });

      this.logger.log(
        `🔄 Regenerated ${newBackupCodes.length} backup codes for user: ${user.email}`,
      );

      return {
        backupCodes: newBackupCodes,
      };
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException
      ) {
        throw error;
      }

      this.logger.error(
        `Failed to regenerate backup codes for user ${userId}:`,
        error.message,
      );
      throw new InternalServerErrorException(
        'Failed to regenerate backup codes',
      );
    }
  }

  async getTwoFactorStatus(userId: string): Promise<TwoFactorStatusResponse> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new BadRequestException('User not found');
    return {
      isEnabled: user.isTwoFactorEnabled,
      hasSecret: !!user.twoFactorSecret,
    };
  }

  async generateBackupCodes(
    userId: string,
    dto: GenerateBackupCodesDto,
  ): Promise<TwoFactorEnableResponse> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new BadRequestException('User not found');
    if (!user.isTwoFactorEnabled)
      throw new BadRequestException('2FA not enabled for this account');
    if (!user.twoFactorSecret)
      throw new BadRequestException('2FA secret not found');

    // Verify the TOTP code
    const isValid = await this.verifyTwoFactorCode(userId, dto.totpCode);
    if (!isValid) {
      throw new UnauthorizedException('Invalid verification code');
    }

    // Generate new backup codes
    const newBackupCodes = Array.from({ length: 10 }, () =>
      Math.random().toString(36).slice(2, 10).toUpperCase(),
    );

    // Hash the new backup codes
    const hashedBackupCodes = await Promise.all(
      newBackupCodes.map((code) => bcrypt.hash(code, 12)),
    );

    // Update user with new hashed backup codes
    await this.usersService.update(userId, {
      backupCodes: {
        set: hashedBackupCodes,
      },
    });

    this.logger.log(
      `✅ Generated ${newBackupCodes.length} backup codes for user: ${user.email}`,
    );

    return {
      backupCodes: newBackupCodes,
    };
  }

  private async sendVerificationEmailAsync(email: string, token: string) {
    try {
      await this.mailService.sendVerificationEmail(email, token);
    } catch (error) {
      this.logger.error(
        `Failed to send verification email to ${email}:`,
        error.message,
      );
    }
  }

  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      return;
    }

    const resetToken = require('crypto').randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000);

    await this.usersService.updateResetToken(
      user.id,
      resetToken,
      resetTokenExpires,
    );

    await this.sendPasswordResetEmailAsync(user.email, resetToken);
  }

  async resetPassword(token: string, password: string): Promise<void> {
    const user = await this.usersService.findByResetToken(token);
    if (!user) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    await this.usersService.resetPassword(user.id, hashedPassword);

    // Ensure LOCAL auth provider exists after password reset
    const existingLocalProvider = await this.prisma.authProvider.findUnique({
      where: {
        userId_provider: {
          userId: user.id,
          provider: this.mapStringToProviderEnum('local'),
        },
      },
    });

    if (!existingLocalProvider) {
      // Create LOCAL auth provider if it doesn't exist
      await this.prisma.authProvider.create({
        data: {
          userId: user.id,
          provider: this.mapStringToProviderEnum('local'),
          providerId: user.email,
          email: user.email,
          isPrimary: true, // Set as primary for password reset
        },
      });
      this.logger.log(`✅ Created LOCAL auth provider for user: ${user.email}`);
    }
  }

  private async sendPasswordResetEmailAsync(email: string, token: string) {
    try {
      await this.mailService.sendPasswordResetEmail(email, token);
    } catch (error) {
      this.logger.error(
        `Failed to send password reset email to ${email}:`,
        error.message,
      );
    }
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      if (!user.password) {
        throw new BadRequestException(
          'Password change not available for social login accounts',
        );
      }

      const isCurrentPasswordValid = await bcrypt.compare(
        currentPassword,
        user.password,
      );
      if (!isCurrentPasswordValid) {
        throw new UnauthorizedException('Current password is incorrect');
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 12);

      await this.usersService.update(userId, {
        password: hashedNewPassword,
      });

      this.logger.log(`Password changed successfully for user: ${user.email}`);
    } catch (error) {
      this.logger.error(
        `Failed to change password for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  async generateEmailVerificationToken(email: string): Promise<string> {
    try {
      const payload: JwtPayload = {
        email,
        type: 'verification',
        sub: email, // Use email as subject for verification
      };

      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      if (!jwtSecret) throw new Error('JWT_SECRET missing');

      // Use 24 hours expiry for email verification
      const verificationToken = await this.jwtService.signAsync(payload, {
        secret: jwtSecret,
        expiresIn: '24h', // Email verification links are typically valid for 24 hours
        noTimestamp: false,
      });

      return verificationToken;
    } catch (error) {
      this.logger.error(
        'Failed to generate email verification token:',
        error.message,
      );
      throw new InternalServerErrorException(
        'Failed to generate verification token',
      );
    }
  }

  async resendVerificationEmail(email: string): Promise<void> {
    try {
      // Find user by email
      const user = await this.usersService.findByEmail(email);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Check if email is already verified
      if (user.isEmailVerified) {
        throw new BadRequestException('Email is already verified');
      }

      // Generate new verification token (always new token as required)
      const emailVerificationToken =
        await this.generateEmailVerificationToken(email);

      // Update user's verification token (for backward compatibility)
      await this.usersService.update(user.id, {
        verificationToken: emailVerificationToken,
      });

      // Send verification email with new token
      this.sendVerificationEmailAsync(email, emailVerificationToken);

      this.logger.log(
        `✅ Verification email resent to: ${email} with new token`,
      );
    } catch (error) {
      if (
        error instanceof NotFoundException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }

      this.logger.error('Failed to resend verification email:', error.message);
      throw new InternalServerErrorException(
        'Failed to resend verification email',
      );
    }
  }

  async generateGTMPermissionToken(
    userId: string,
    context?: any,
  ): Promise<{ permissionToken: string; expiresIn: number; issuedAt: number }> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Verify user has Google authentication configured
      const googleProvider = await this.prisma.authProvider.findFirst({
        where: {
          userId: userId,
          provider: 'GOOGLE',
        },
      });

      if (!googleProvider?.accessToken) {
        throw new UnauthorizedException(
          'Google authentication required for GTM access. Please authenticate with Google first.',
        );
      }

      // Generate permission token with GTM-specific permissions
      // Optimize payload by only including context if it has meaningful data
      const payload: any = {
        sub: userId,
        email: user.email,
        type: this.GTM_TOKEN_TYPE,
        permissions: this.GTM_PERMISSIONS,
      };

      // Only include context if it has meaningful data
      if (context && Object.keys(context).length > 0) {
        payload.context = context;
      }

      // Use standard expiresIn approach instead of manual exp to avoid conflicts
      const permissionToken = await this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_SECRET'),
        expiresIn: this.GTM_TOKEN_EXPIRY,
        noTimestamp: false, // Keep iat for additional security
        audience: 'stargate-gtm', // Specific audience for GTM tokens
        issuer: 'stargate-auth', // Specific issuer for clarity
      });

      // Calculate expiresIn for 15 minute token
      const EXPIRES_IN_15_MINUTES = 15 * 60 * 1000; // 900,000 ms

      return {
        permissionToken,
        expiresIn: EXPIRES_IN_15_MINUTES,
        issuedAt: Date.now(),
      };
    } catch (error) {
      this.logger.error(
        `Failed to generate GTM permission token for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }
}
