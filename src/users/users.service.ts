import { Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from '@prisma/client';
import { LoggerService } from 'src/utils/logger/logger.service';
import { PrismaService } from '../database/prisma/prisma.service';

// Define JwtPayload interface locally to avoid circular dependencies
interface JwtPayload {
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
}

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private logger: LoggerService,
  ) {}

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  async findById(id: string) {
    return this.prisma.user.findUnique({
      where: { id },
    });
  }

  async findByVerificationToken(token: string) {
    return this.prisma.user.findFirst({
      where: {
        verificationToken: token,
        // Ensure token is not null and not expired (optional)
        // You could add expiration logic here if needed
      },
    });
  }

  async markEmailAsVerified(
    userId: string,
  ): Promise<{ user: any; wasAlreadyVerified: boolean }> {
    // First, check if the user is already verified
    const user = await this.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const wasAlreadyVerified = user.isEmailVerified;

    if (wasAlreadyVerified) {
      // Return user without updating the database
      return { user, wasAlreadyVerified: true };
    }

    // Update user if not already verified
    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: {
        isEmailVerified: true,
        emailVerifiedAt: new Date(),
        verificationToken: null,
      },
    });

    return { user: updatedUser, wasAlreadyVerified: false };
  }

  async create(data: {
    email: string;
    name: string;
    password?: string;
    avatar?: string | null;
    provider?: string; // Keep for backward compatibility but don't use in DB
    isEmailVerified?: boolean;
    emailVerifiedAt?: Date | null;
    verificationToken?: string | null;
  }) {
    return this.prisma.user.create({
      data: {
        email: data.email,
        name: data.name,
        password: data.password || null,
        avatar: data.avatar || null,
        isEmailVerified: data.isEmailVerified ?? false,
        emailVerifiedAt: data.emailVerifiedAt || null,
        verificationToken: data.verificationToken || null,
      },
    });
  }

  async update(id: string, data: Prisma.UserUpdateInput) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    return this.prisma.user.update({ where: { id }, data });
  }

  async delete(id: string) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    return this.prisma.user.delete({ where: { id } });
  }

  async findAll() {
    return this.prisma.user.findMany({
      select: {
        id: true,
        email: true,
        name: true,
        avatar: true,
        isEmailVerified: true,
        createdAt: true,
        updatedAt: true,
        // Don't include password in the response
      },
    });
  }

  // Add these methods to the UsersService class
  async findByResetToken(token: string) {
    return this.prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpires: {
          gt: new Date(), // Check if token is still valid
        },
      },
    });
  }

  async updateResetToken(
    userId: string,
    resetToken: string,
    resetTokenExpires: Date,
  ) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        resetToken,
        resetTokenExpires,
      },
    });
  }

  async resetPassword(userId: string, password: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        password,
        resetToken: null,
        resetTokenExpires: null,
      },
    });
  }

  async changePassword(userId: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    return this.prisma.user.update({
      where: { id: userId },
      data: { password },
    });
  }

  // Enhanced verification token logic for JWT-based tokens
  async verifyEmailToken(
    token: string,
  ): Promise<{ email: string; user?: any; tokenValid: boolean }> {
    try {
      // First try to decode as JWT token (new format)
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      if (!jwtSecret) {
        throw new Error('JWT_SECRET missing');
      }

      const decoded = (await this.jwtService.verifyAsync(token, {
        secret: jwtSecret,
      })) as JwtPayload;

      // Check if this is a verification token with email
      if (decoded.email && decoded.type === 'verification') {
        // Find user by email to check verification status
        const user = await this.findByEmail(decoded.email);

        return {
          email: decoded.email,
          user,
          tokenValid: true,
        };
      }

      throw new Error('Invalid token format');
    } catch (jwtError) {
      // If JWT verification failed, try legacy database lookup
      this.logger.warn(
        'JWT verification failed, trying legacy token lookup',
        'UsersService',
        {
          error: jwtError.message,
        },
      );

      const user = await this.prisma.user.findFirst({
        where: {
          verificationToken: token,
        },
      });

      if (user) {
        return {
          email: user.email,
          user,
          tokenValid: true,
        };
      }

      return { email: '', tokenValid: false };
    }
  }

  // API Key support for bash-runner compatibility
  async findByApiKey(apiKey: string) {
    // For now, return null as stargate doesn't use API keys by default
    // This can be extended later if API key support is needed
    return null;
  }

  async getMetrics(userId: string) {
    // Get counts for sgtm containers
    const sgtmTotal = await this.prisma.sgtmContainer.count({
      where: { userId },
    });

    const sgtmActive = await this.prisma.sgtmContainer.count({
      where: { userId, status: 'RUNNING' },
    });

    const sgtmDisabled = await this.prisma.sgtmContainer.count({
      where: {
        userId,
        status: { in: ['STOPPED', 'ERROR', 'DELETED'] },
      },
    });

    // Get counts for meta capi containers
    const mcapiTotal = await this.prisma.metaCapiContainer.count({
      where: { userId },
    });

    const mcapiActive = await this.prisma.metaCapiContainer.count({
      where: { userId, status: 'RUNNING' },
    });

    const mcapiDisabled = await this.prisma.metaCapiContainer.count({
      where: {
        userId,
        status: { in: ['STOPPED', 'ERROR', 'DELETED'] },
      },
    });

    return {
      totalContainers: sgtmTotal + mcapiTotal,
      activeContainers: sgtmActive + mcapiActive,
      disabledContainers: sgtmDisabled + mcapiDisabled,
    };
  }
}
