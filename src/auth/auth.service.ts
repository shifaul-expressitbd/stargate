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
import { PrismaService } from '../database/prisma/prisma.service';
import { MailService } from '../mail/mail.service';
import { UsersService } from '../users/users.service';
import { RegenerateBackupCodesDto } from './dto/backup-code.dto';
import { RegisterDto } from './dto/register.dto';
import { LoginWithTwoFactorDto } from './dto/two-factor.dto';

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
  currentCode?: string;
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
    window: 2,
    step: 30,
  };

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    private readonly prisma: PrismaService,
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

    console.log('JWT Secrets Debug:', {
      jwtSecret: jwtSecret ? `${jwtSecret.substring(0, 10)}...` : 'NOT FOUND',
      jwtRefreshSecret: jwtRefreshSecret
        ? `${jwtRefreshSecret.substring(0, 10)}...`
        : 'NOT FOUND',
      timestamp: new Date().toISOString(),
      testIdentifier: process.env.TEST_NAME || 'unknown',
    });

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

  async loginWithTwoFactor(dto: LoginWithTwoFactorDto): Promise<AuthResponse> {
    try {
      const { tempToken, code, rememberMe = false } = dto;

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

      const isValidCode = await this.verifyTwoFactorCode(user.id, code);
      if (!isValidCode) {
        throw new UnauthorizedException('Invalid 2FA code');
      }

      const tokens = await this.generateTokens(
        user.id,
        user.email,
        user.roles,
        rememberMe,
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
   * Creates a new user session with device information
   */
  async createUserSession(
    userId: string,
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
    deviceInfo?: any,
  ): Promise<UserSession> {
    try {
      // Calculate session expiry
      const sessionExpiryHours = rememberMe ? 30 * 24 : 24; // 30 days or 24 hours
      const expiresAt = new Date(
        Date.now() + sessionExpiryHours * 60 * 60 * 1000,
      );

      // Generate unique session ID
      const sessionId = require('crypto').randomBytes(32).toString('hex');

      const session = await this.prisma.userSession.create({
        data: {
          userId,
          sessionId,
          deviceInfo,
          ipAddress,
          userAgent,
          rememberMe,
          expiresAt,
        },
      });

      this.logger.log(`✅ Created session ${sessionId} for user ${userId}`);
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

  async generateTokens(
    userId: string,
    email: string,
    roles: string[],
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
    deviceInfo?: any,
  ): Promise<RefreshTokenResponse> {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      const refreshSecret =
        this.configService.get<string>('JWT_REFRESH_SECRET');
      if (!jwtSecret || !refreshSecret) throw new Error('JWT secrets missing');

      // Generate session expiry and refresh token expiry
      const sessionExpiryHours = rememberMe ? 30 * 24 : 24; // 30 days or 24 hours
      const refreshTokenExpiryHours = rememberMe ? 30 * 24 : 7 * 24; // 30 days or 7 days

      // Create user session
      const session = await this.createUserSession(
        userId,
        rememberMe,
        ipAddress,
        userAgent,
        deviceInfo,
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

      const tokens = await this.generateTokens(user.id, user.email, user.roles);

      const {
        password,
        verificationToken,
        twoFactorSecret,
        refreshTokenHash,
        ...userResult
      } = user;

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

      // Manual construction for better issuer support
      const otpAuthUrl = `otpauth://totp/${encodeURIComponent(`${issuer}:${accountName}`)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

      // Handle QR code generation with proper error checking
      try {
        const qr = QRCode(0, 'L');
        qr.addData(otpAuthUrl);
        qr.make();
        const qrCodeUrl = qr.createDataURL(4);

        await this.usersService.update(userId, {
          twoFactorSecret: secret,
        });

        const currentCode = totp.generate(secret);

        const result = {
          secret,
          qrCodeUrl,
          manualEntryKey: secret,
          otpAuthUrl,
          currentCode:
            process.env.NODE_ENV === 'development' ? currentCode : undefined,
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

  async verifyTwoFactorCode(userId: string, code: string): Promise<boolean> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user || !user.twoFactorSecret) {
        this.logger.warn(`No 2FA secret found for user: ${userId}`);
        return false;
      }

      const cleanCode = code.replace(/\s/g, '').padStart(6, '0');

      if (!/^\d{6}$/.test(cleanCode)) {
        this.logger.warn(`Invalid code format: ${cleanCode}`);
        return false;
      }

      const secret = user.twoFactorSecret;
      const isValid = totp.check(cleanCode, secret);

      if (isValid) {
        this.logger.log(`✅ 2FA code verified for user: ${user.email}`);
        return true;
      }

      const currentTime = Math.floor(Date.now() / 1000);
      const timeStep = 30;
      const windowSize = 3;

      for (let i = -windowSize; i <= windowSize; i++) {
        const testTime = currentTime + i * timeStep;
        try {
          const timeBasedCode = this.generateTOTPCode(
            secret,
            Math.floor(testTime / timeStep),
          );

          if (timeBasedCode === cleanCode) {
            this.logger.log(
              `✅ 2FA code verified for user: ${user.email} (time offset: ${i * 30}s)`,
            );
            return true;
          }
        } catch (error) {
          this.logger.debug(
            `Error generating code for time offset ${i * 30}s:`,
            error.message,
          );
        }
      }

      const currentExpected = totp.generate(secret);
      const serverTime = new Date().toISOString();
      const serverTimestamp = Math.floor(Date.now() / 1000);

      this.logger.warn(`❌ No matching code found for user: ${user.email}`);
      this.logger.debug(`Current expected code: ${currentExpected}`);
      this.logger.debug(`Received code: ${cleanCode}`);
      this.logger.debug(`Server time: ${serverTime} (${serverTimestamp})`);
      this.logger.debug(`Checked time window: ${-windowSize * timeStep}s to +${windowSize * timeStep}s`);

      // Log expected codes at different time offsets for debugging
      for (let i = -windowSize; i <= windowSize; i++) {
        const testTime = currentTime + i * timeStep;
        try {
          const testCode = this.generateTOTPCode(secret, Math.floor(testTime / timeStep));
          this.logger.debug(`Expected code at offset ${i * timeStep}s: ${testCode} (time: ${new Date(testTime * 1000).toISOString()})`);
        } catch (error) {
          this.logger.debug(`Error calculating code for offset ${i * timeStep}s: ${error.message}`);
        }
      }

      // Provide debugging info in the warning
      this.logger.warn(`⏰ Time sync debugging for user ${userId}:`);
      this.logger.warn(`📱 Ensure authenticator app is time-synced with NTP server`);
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

  async enableTwoFactor(
    userId: string,
    code: string,
    skipBackup = false,
  ): Promise<TwoFactorEnableResponse> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new BadRequestException('User not found');
    if (user.isTwoFactorEnabled)
      throw new BadRequestException('2FA already enabled');
    if (!user.twoFactorSecret) {
      throw new BadRequestException(
        'No 2FA secret generated. Run /2fa/generate first.',
      );
    }

    const isValid = await this.verifyTwoFactorCode(userId, code);
    if (!isValid) {
      const currentCode = totp.generate(user.twoFactorSecret);
      const timeInfo = `Current server time: ${new Date().toISOString()}`;

      this.logger.warn(
        `2FA enable failed for ${user.email}: Expected=${currentCode}, Received=${code}`,
      );
      this.logger.warn(`Time sync issue? ${timeInfo}`);

      throw new UnauthorizedException(
        `Invalid verification code. Server expected: ${currentCode} (${timeInfo}). ` +
        'Please check your device time synchronization.',
      );
    }

    const backupCodes = skipBackup
      ? []
      : Array.from({ length: 8 }, () =>
        Math.random().toString(36).slice(2, 10).toUpperCase(),
      );

    const hashedBackupCodes = await Promise.all(
      backupCodes.map((code) => bcrypt.hash(code, 12)),
    );

    this.logger.log(
      `🔐 Generated ${backupCodes.length} backup codes for user: ${user.email}`,
    );

    await this.usersService.update(userId, {
      isTwoFactorEnabled: true,
      backupCodes: {
        set: hashedBackupCodes,
      },
    });

    this.logger.log(
      `📝 Stored ${hashedBackupCodes.length} hashed backup codes for user: ${user.email}`,
    );
    this.logger.log(`✅ 2FA enabled for user: ${user.email}`);

    return {
      ...(backupCodes.length > 0 && { backupCodes }),
    };
  }

  async disableTwoFactor(userId: string, code: string): Promise<void> {
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

    const isValid = await this.verifyTwoFactorCode(userId, code);
    if (!isValid) {
      const expectedCode = totp.generate(user.twoFactorSecret);
      this.logger.debug(
        `Expected code during disable: ${expectedCode}, Received: ${code}`,
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
      const isValid = await this.verifyTwoFactorCode(
        userId,
        dto.verificationCode,
      );
      if (!isValid) {
        const currentCode = totp.generate(user.twoFactorSecret);
        this.logger.warn(
          `2FA regeneration failed for ${user.email}: Expected=${currentCode}, Received=${dto.verificationCode}`,
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
