import {
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../../database/prisma/prisma.service';
import { UsersService } from '../../users/users.service';

export interface JwtPayload {
  sub: string;
  email: string;
  roles?: string[];
  type?: string;
  permissions?: string[];
  iat?: number;
  exp?: number;
  impersonatedBy?: string;
  rememberMe?: boolean;
  impersonatorEmail?: string;
  isImpersonation?: boolean;
  sessionId?: string;
  tokenFamily?: string;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  session: any;
}

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);
  private readonly appName = 'StarGate Platform';

  // GTM Permission Token Configuration
  private readonly GTM_PERMISSIONS = [
    'gtm.accounts.read',
    'gtm.containers.read',
    'gtm.tags.read',
  ] as const;

  private readonly GTM_TOKEN_TYPE = 'gtm-permission';
  private readonly GTM_TOKEN_EXPIRY = '15m';

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
  ) {}

  /**
   * Generate JWT tokens with session management
   */
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

      if (!jwtSecret || !refreshSecret) {
        throw new Error('JWT secrets missing');
      }

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
        sessionId: session.sessionId,
        tokenFamily: require('crypto').randomBytes(16).toString('hex'),
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

  /**
   * Validate and consume a refresh token
   */
  async validateAndConsumeRefreshToken(
    refreshToken: string,
    userId: string,
  ): Promise<{ session: any; tokenFamily: string | null }> {
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
                isActive: false,
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
   * Generate GTM permission token for accessing Google Tag Manager APIs
   */
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
        noTimestamp: false,
        audience: 'stargate-gtm',
        issuer: 'stargate-auth',
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

  /**
   * Generate email verification token
   */
  async generateEmailVerificationToken(email: string): Promise<string> {
    try {
      const payload: JwtPayload = {
        email,
        type: 'verification',
        sub: email,
      };

      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      if (!jwtSecret) throw new Error('JWT_SECRET missing');

      const verificationToken = await this.jwtService.signAsync(payload, {
        secret: jwtSecret,
        expiresIn: '24h',
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

  /**
   * Validate JWT secrets
   */
  validateJWTSecrets(): void {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const jwtRefreshSecret =
      this.configService.get<string>('JWT_REFRESH_SECRET');

    this.logger.log(
      `🔐 [TokenService] Validating JWT secrets at ${new Date().toISOString()}`,
    );
    this.logger.log(
      `🔐 [TokenService] JWT_SECRET length: ${jwtSecret?.length || 'undefined'}`,
    );
    this.logger.log(
      `🔐 [TokenService] JWT_REFRESH_SECRET length: ${jwtRefreshSecret?.length || 'undefined'}`,
    );

    if (!jwtSecret || jwtSecret.length < 32) {
      this.logger.error(
        `❌ [TokenService] JWT_SECRET validation failed: ${!jwtSecret ? 'NOT FOUND' : `too short (${jwtSecret.length} chars)`}`,
      );
      throw new Error(
        `JWT_SECRET is missing or too short (minimum 32 characters). Found length: ${jwtSecret?.length || 'undefined'}`,
      );
    }

    if (!jwtRefreshSecret || jwtRefreshSecret.length < 32) {
      this.logger.error(
        `❌ [TokenService] JWT_REFRESH_SECRET validation failed: ${!jwtRefreshSecret ? 'NOT FOUND' : `too short (${jwtRefreshSecret.length} chars)`}`,
      );
      throw new Error(
        `JWT_REFRESH_SECRET is missing or too short (minimum 32 characters). Found length: ${jwtRefreshSecret?.length || 'undefined'}`,
      );
    }

    this.logger.log('✅ [TokenService] JWT secrets validated successfully');
  }

  /**
   * Decode and verify JWT token without throwing errors
   */
  async decodeToken(token: string): Promise<JwtPayload | null> {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      if (!jwtSecret) return null;

      const payload = await this.jwtService.verifyAsync(token, {
        secret: jwtSecret,
      });

      return payload;
    } catch (error) {
      this.logger.warn('Failed to decode token:', error.message);
      return null;
    }
  }

  /**
   * Check if token is expired
   */
  async isTokenExpired(token: string): Promise<boolean> {
    try {
      const decoded = await this.decodeToken(token);
      if (!decoded) return true;

      const now = Math.floor(Date.now() / 1000);
      return (decoded.exp || 0) < now;
    } catch (error) {
      return true;
    }
  }

  /**
   * Extract token metadata without verification
   */
  extractTokenMetadata(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      return {
        sub: payload.sub,
        email: payload.email,
        type: payload.type,
        permissions: payload.permissions,
        iat: payload.iat,
        exp: payload.exp,
        sessionId: payload.sessionId,
        tokenFamily: payload.tokenFamily,
      };
    } catch (error) {
      this.logger.warn('Failed to extract token metadata:', error.message);
      return null;
    }
  }

  /**
   * Create user session (internal helper)
   */
  private async createUserSession(
    userId: string,
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
    deviceInfo?: any,
    additionalHeaders?: Record<string, string>,
  ): Promise<any> {
    try {
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
      const sessionExpiryHours = rememberMe ? 30 * 24 : 24;
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
        deviceFingerprintConfidence: 0.8,
        latitude: geolocation.latitude,
        longitude: geolocation.longitude,
        timezone: geolocation.timezone,
        rememberMe,
        expiresAt,
      };

      const session = await this.prisma.userSession.create({
        data: sessionData,
      });

      this.logger.log(
        `✅ Created enhanced session ${sessionId} for user ${userId}`,
      );
      return session;
    } catch (error) {
      this.logger.error(
        `Failed to create user session for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Store refresh token (internal helper)
   */
  private async storeRefreshToken(
    sessionId: string,
    refreshToken: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    try {
      const tokenHash = await bcrypt.hash(refreshToken, 12);
      const tokenFamily = require('crypto').randomBytes(16).toString('hex');

      const rememberMeSession = await this.prisma.userSession.findUnique({
        where: { id: sessionId },
        select: { rememberMe: true },
      });
      const tokenExpiryHours = rememberMeSession?.rememberMe ? 30 * 24 : 7 * 24;
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
   * Generate browser fingerprint hash (helper)
   */
  private generateBrowserFingerprintHash(
    userAgent: string,
    additionalHeaders?: Record<string, string>,
  ): string {
    try {
      const crypto = require('crypto');
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
   * Detect geolocation from IP (helper)
   */
  private async detectGeolocation(ipAddress: string): Promise<{
    latitude?: number;
    longitude?: number;
    timezone?: string;
    location?: string;
  }> {
    try {
      if (this.isPrivateIP(ipAddress)) {
        return { location: 'Local Network' };
      }

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

  private guessTimezoneFromIP(ip: string): string {
    if (!ip || ip === 'unknown' || ip === '::1') {
      return 'UTC';
    }
    return 'Asia/Dhaka';
  }

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
}
