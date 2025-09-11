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
import { LoggerService } from 'src/utils/logger/logger.service';
import { PrismaService } from '../../database/prisma/prisma.service';
import { MailService } from '../../mail/mail.service';
import { UsersService } from '../../users/users.service';

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

@Injectable()
export class AuthCoreService {
  private readonly logger = new Logger(AuthCoreService.name);
  private readonly appName = 'StarGate Platform';

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    private readonly prisma: PrismaService,
    private readonly loggerService: LoggerService,
  ) {}

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

  async register(registerDto: any): Promise<AuthResponse> {
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

  async generateTokens(
    userId: string,
    email: string,
    roles: string[],
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
    deviceInfo?: any,
    additionalHeaders?: Record<string, string>,
  ): Promise<{ accessToken: string; refreshToken: string; session: any }> {
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

      this.logger.log(
        `✅ Created enhanced session ${sessionId} for user ${userId}`,
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

  private async detectGeolocation(ipAddress: string): Promise<{
    latitude?: number;
    longitude?: number;
    timezone?: string;
    location?: string;
  }> {
    try {
      // Skip geolocation for private/local IPs
      if (this.isPrivateIP(ipAddress)) {
        return { location: 'Local Network' };
      }

      // Simple timezone detection based on IP (this is very basic)
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
    // Default to UTC
    if (!ip || ip === 'unknown' || ip === '::1') {
      return 'UTC';
    }

    // For demonstration, we'll use a simple mapping
    return 'Asia/Dhaka'; // Default for this example
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

  private async storeRefreshToken(
    sessionId: string,
    refreshToken: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
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

  async loginWithTwoFactor(
    dto: any,
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

  private async verifyTwoFactorCode(
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
      const currentExpected = this.generateTOTPCode(secret);
      this.logger.debug(`Current expected code: ${currentExpected}`);
      this.logger.debug(`Received code: ${cleanCode}`);

      // Manual window check with logging
      const currentTime = Math.floor(Date.now() / 1000);
      const timeStep = 30;
      const windowSize = 3;
      const isValid = this.checkTOTPCode(cleanCode, secret);

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
      this.logger.debug(`Checked time window: ±${3 * 30}s`);

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

  private generateTOTPCode(secret: string, timeCounter?: number): string {
    try {
      const crypto = require('crypto');
      const counter = timeCounter || Math.floor(Date.now() / 1000 / 30);
      const buffer = Buffer.allocUnsafe(8);
      buffer.writeUInt32BE(0, 0);
      buffer.writeUInt32BE(counter, 4);

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
      this.logger.debug(`TOTP Code: ${finalCode} (time: ${counter})`);

      return finalCode;
    } catch (error) {
      const { totp } = require('otplib');
      return totp.generate(secret);
    }
  }

  private checkTOTPCode(code: string, secret: string): boolean {
    try {
      const { totp } = require('otplib');
      return totp.check(code, secret);
    } catch (error) {
      this.logger.warn('Failed to check TOTP code:', error.message);
      return false;
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

  private async logAccessEvent(
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
}
