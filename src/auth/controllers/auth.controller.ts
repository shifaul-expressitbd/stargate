import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  NotFoundException,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';

import { ConfigService } from '@nestjs/config';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { Public } from '../../common/decorators/public.decorator';
import { User } from '../../common/decorators/user.decorator';
import { UrlConfigService } from '../../config/url.config';
import { PrismaService } from '../../database/prisma/prisma.service';
import { UsersService } from '../../users/users.service';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { ResendVerificationEmailDto } from '../dto/resend-verification-email.dto';
import { ForgotPasswordDto, ResetPasswordDto } from '../dto/reset-password.dto';
import { AuthCoreService } from '../services/auth-core.service';
import { SessionService } from '../services/session.service';
import { TokenService } from '../services/token.service';

interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  code?: string;
}

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authCoreService: AuthCoreService,
    private readonly sessionService: SessionService,
    private readonly tokenService: TokenService,
    private readonly usersService: UsersService,
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly urlConfigService: UrlConfigService,
  ) {}

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

  // ========== REGISTER ==========
  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @ApiOperation({ summary: 'Register a new user with email and password' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['email', 'name', 'password'],
      properties: {
        email: {
          type: 'string',
          format: 'email',
          example: 'user@example.com',
        },
        name: {
          type: 'string',
          example: 'John Doe',
        },
        password: {
          type: 'string',
          minLength: 8,
          example: 'password123',
        },
        avatar: {
          type: 'string',
          example: 'https://example.com/avatar.jpg',
        },
      },
    },
  })
  @ApiResponse({
    status: 201,
    description: 'User registered successfully',
    schema: {
      example: {
        success: true,
        message:
          'Registration successful. Please check your email for verification.',
        data: {
          user: {
            id: 'uuid',
            email: 'user@example.com',
            name: 'John Doe',
            avatar: 'https://example.com/avatar.jpg',
            provider: 'local',
            isEmailVerified: false,
            isTwoFactorEnabled: false,
          },
          accessToken: 'jwt-token',
          refreshToken: 'refresh-token',
        },
      },
    },
  })
  async register(@Body() registerDto: RegisterDto): Promise<ApiResponse> {
    try {
      const result = await this.authCoreService.register(registerDto);
      return this.createSuccessResponse(
        'Registration successful. Please check your email for verification.',
        result,
      );
    } catch (error) {
      this.logger.error('Registration failed:', error.message);

      if (error instanceof BadRequestException) {
        throw new BadRequestException(
          this.createErrorResponse(
            error.message,
            'VALIDATION_ERROR',
            'VALIDATION_FAILED',
          ),
        );
      }

      if (error instanceof ConflictException) {
        throw new ConflictException(
          this.createErrorResponse(error.message, 'CONFLICT', 'USER_EXISTS'),
        );
      }

      throw new BadRequestException(
        this.createErrorResponse(
          'Registration failed. Please try again.',
          'SERVER_ERROR',
          'REGISTRATION_FAILED',
        ),
      );
    }
  }

  // ========== LOGIN ==========
  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards() // Local strategy guard will be applied at service level
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['email', 'password'],
      properties: {
        email: {
          type: 'string',
          format: 'email',
          example: 'user@example.com',
        },
        password: {
          type: 'string',
          example: 'password123',
        },
        rememberMe: {
          type: 'boolean',
          example: true,
          description: 'Extend refresh token expiry if true',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    schema: {
      example: {
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: 'uuid',
            email: 'user@example.com',
            name: 'John Doe',
            avatar: 'https://example.com/avatar.jpg',
            provider: 'local',
            isEmailVerified: true,
            isTwoFactorEnabled: false,
          },
          accessToken: 'jwt-token',
          refreshToken: 'refresh-token',
        },
      },
    },
  })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
  ): Promise<ApiResponse> {
    try {
      // First validate user credentials
      const user = await this.authCoreService.validateUser(
        loginDto.email,
        loginDto.password,
      );

      const result = await this.authCoreService.login(
        user,
        loginDto.rememberMe,
        req.ip,
        req.get('User-Agent'),
      );

      if ('requiresTwoFactor' in result) {
        return this.createSuccessResponse(
          'Two-factor authentication required',
          result,
        );
      }

      return this.createSuccessResponse('Login successful', result);
    } catch (error) {
      this.logger.error('Login failed:', error.message);

      if (error instanceof UnauthorizedException) {
        throw new UnauthorizedException(
          this.createErrorResponse(
            error.message,
            'UNAUTHORIZED',
            'INVALID_CREDENTIALS',
          ),
        );
      }

      throw new UnauthorizedException(
        this.createErrorResponse(
          'Login failed. Please try again.',
          'AUTH_ERROR',
          'LOGIN_FAILED',
        ),
      );
    }
  }

  // ========== REFRESH TOKEN ==========
  @Public()
  @UseGuards() // Refresh token strategy guard will be applied at service level
  @Get('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refresh access token using a valid refresh token',
  })
  @ApiResponse({
    status: 200,
    description: 'Token refreshed successfully',
    schema: {
      example: {
        success: true,
        message: 'Token refreshed successfully',
        data: {
          user: {
            id: 'uuid',
            email: 'user@example.com',
            name: 'John Doe',
            avatar: 'https://example.com/avatar.jpg',
            provider: 'local',
            isEmailVerified: true,
            isTwoFactorEnabled: false,
          },
          accessToken: 'jwt-token',
          refreshToken: 'refresh-token',
        },
      },
    },
  })
  async refresh(@Req() req: Request, @User() user: any): Promise<ApiResponse> {
    try {
      // Extract refresh token from Authorization header
      const authHeader = req.get('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        this.logger.warn(
          'Missing or invalid Authorization header for refresh token',
        );
        throw new UnauthorizedException(
          this.createErrorResponse(
            'Authorization header missing or invalid',
            'UNAUTHORIZED',
            'INVALID_AUTHORIZATION_HEADER',
          ),
        );
      }

      const refreshToken = authHeader.substring(7);
      if (!refreshToken || refreshToken.trim() === '') {
        this.logger.warn(
          'Empty refresh token extracted from Authorization header',
        );
        throw new UnauthorizedException(
          this.createErrorResponse(
            'Refresh token missing from Authorization header',
            'UNAUTHORIZED',
            'MISSING_REFRESH_TOKEN',
          ),
        );
      }

      // Validate and consume the refresh token
      const { session } =
        await this.tokenService.validateAndConsumeRefreshToken(
          refreshToken,
          user.id,
        );

      // Generate new tokens
      const userEntity = await this.usersService.findById(user.id);
      const result = await this.tokenService.generateTokens(
        user.id,
        user.email,
        user.roles,
        session.rememberMe,
        req.ip,
        req.get('User-Agent'),
      );

      // Get user with auth providers
      const userWithProviders = await this.prisma.user.findUnique({
        where: { id: user.id },
        include: {
          authProviders: {
            select: {
              provider: true,
              isPrimary: true,
            },
          },
        },
      });

      if (!userWithProviders) {
        throw new NotFoundException('User not found');
      }

      const primaryProvider =
        userWithProviders.authProviders?.find((p) => p.isPrimary)?.provider ||
        'local';

      const responseData = {
        user: {
          id: userWithProviders.id,
          email: userWithProviders.email,
          name: userWithProviders.name,
          avatar: userWithProviders.avatar,
          provider: primaryProvider,
          isEmailVerified: userWithProviders.isEmailVerified,
          isTwoFactorEnabled: userWithProviders.isTwoFactorEnabled,
        },
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      };

      return this.createSuccessResponse(
        'Token refreshed successfully',
        responseData,
      );
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;

      this.logger.error('Token refresh failed:', error.message);

      throw new UnauthorizedException(
        this.createErrorResponse(
          'Invalid or expired refresh token',
          'UNAUTHORIZED',
          'INVALID_REFRESH_TOKEN',
        ),
      );
    }
  }

  // ========== VERIFY EMAIL ==========
  @Public()
  @Get('verify-email')
  @ApiOperation({
    summary: 'Verify user email using token',
  })
  @ApiQuery({
    name: 'token',
    description: 'Email verification token sent to user email',
    required: true,
    type: String,
  })
  @ApiResponse({
    status: 200,
    description: 'Email verification successful',
    schema: {
      example: {
        success: true,
        message: 'Email verified successfully',
        data: {
          user: {
            id: 'uuid',
            email: 'user@example.com',
            isEmailVerified: true,
          },
          alreadyVerified: false,
        },
      },
    },
  })
  async verifyEmail(@Query('token') token: string, @Res() res: Response) {
    try {
      if (!token) {
        throw new BadRequestException('Token is required');
      }

      // Use the new enhanced token verification method
      const { email, user, tokenValid } =
        await this.usersService.verifyEmailToken(token);

      if (!tokenValid) {
        throw new BadRequestException('Invalid or expired verification token');
      }

      // If token is valid but no user found (possible with old tokens), reject
      if (!user) {
        throw new BadRequestException('User not found or token has expired');
      }

      const { user: updatedUser, wasAlreadyVerified } =
        await this.usersService.markEmailAsVerified(user.id);

      if (wasAlreadyVerified) {
        this.logger.log(
          `📧 Email already verified for user: ${updatedUser.email}`,
        );

        const response = this.createSuccessResponse(
          'Email is already verified',
          {
            user: {
              id: updatedUser.id,
              email: updatedUser.email,
              isEmailVerified: updatedUser.isEmailVerified,
            },
            alreadyVerified: true,
          },
        );

        return res.json(response);
      } else {
        this.logger.log(`✅ Email verified for user: ${updatedUser.email}`);

        const response = this.createSuccessResponse(
          'Email verified successfully',
          {
            user: {
              id: updatedUser.id,
              email: updatedUser.email,
              isEmailVerified: updatedUser.isEmailVerified,
            },
            alreadyVerified: false,
          },
        );

        return res.json(response);
      }
    } catch (error) {
      this.logger.error('Email verification error:', error.message);

      const errorResponse = this.createErrorResponse(
        error.message,
        'VERIFICATION_FAILED',
        'INVALID_TOKEN',
      );

      return res.status(400).json(errorResponse);
    }
  }

  // ========== RESEND VERIFICATION EMAIL ==========
  @Public()
  @Post('resend-verification-email')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 86400000 } })
  @ApiOperation({ summary: 'Resend verification email with new token' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['email'],
      properties: {
        email: {
          type: 'string',
          format: 'email',
          example: 'user@example.com',
        },
      },
    },
  })
  async resendVerificationEmail(
    @Body() dto: ResendVerificationEmailDto,
  ): Promise<ApiResponse> {
    try {
      await this.authCoreService.resendVerificationEmail(dto.email);
      return this.createSuccessResponse('Verification email sent successfully');
    } catch (error) {
      this.logger.error('Resend verification email failed:', error.message);

      if (error instanceof NotFoundException) {
        throw new NotFoundException(
          this.createErrorResponse(
            error.message,
            'NOT_FOUND',
            'USER_NOT_FOUND',
          ),
        );
      }

      if (error instanceof BadRequestException) {
        throw new BadRequestException(
          this.createErrorResponse(
            error.message,
            'BAD_REQUEST',
            'EMAIL_ALREADY_VERIFIED',
          ),
        );
      }

      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to send verification email',
          'SERVER_ERROR',
          'RESEND_FAILED',
        ),
      );
    }
  }

  // ========== LOGOUT ==========
  @Post('logout')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Logout current user and invalidate current session',
  })
  @ApiResponse({
    status: 200,
    description: 'Logout successful',
    schema: {
      example: {
        success: true,
        message: 'Logged out successfully',
        data: null,
      },
    },
  })
  async logout(@User() user: any): Promise<ApiResponse> {
    try {
      // Extract current session ID from JWT payload
      const currentSessionId = user.sessionId;

      // Log the logout event
      await this.sessionService.logAccessEvent(
        user.id,
        'LOGOUT',
        currentSessionId,
      );

      this.logger.log(
        `User logged out: ${user.email} (Session: ${currentSessionId || 'unknown'})`,
      );
      return this.createSuccessResponse('Logged out successfully');
    } catch (error) {
      this.logger.error('Logout failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to logout',
          'LOGOUT_ERROR',
          'LOGOUT_FAILED',
        ),
      );
    }
  }

  // ========== PASSWORD RESET ==========
  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.ACCEPTED)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({ summary: 'Request password reset email' })
  async forgotPassword(
    @Body() { email }: ForgotPasswordDto,
  ): Promise<ApiResponse> {
    try {
      await this.authCoreService.requestPasswordReset(email);
      return this.createSuccessResponse(
        'If an account with this email exists, a password reset link has been sent.',
      );
    } catch (error) {
      this.logger.error('Password reset request failed:', error.message);
      // Don't reveal if email exists or not for security
      return this.createSuccessResponse(
        'If an account with this email exists, a password reset link has been sent.',
      );
    }
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password using token' })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<ApiResponse> {
    try {
      await this.authCoreService.resetPassword(
        resetPasswordDto.token,
        resetPasswordDto.password,
      );
      return this.createSuccessResponse('Password reset successfully');
    } catch (error) {
      this.logger.error('Password reset failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          error.message,
          'PASSWORD_RESET_ERROR',
          'RESET_FAILED',
        ),
      );
    }
  }

  // ========== CHANGE PASSWORD ==========
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Post('change-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Change password' })
  async changePassword(
    @User('id') userId: string,
    @Body() changePasswordDto: ChangePasswordDto,
  ): Promise<ApiResponse> {
    try {
      await this.authCoreService.changePassword(
        userId,
        changePasswordDto.currentPassword,
        changePasswordDto.newPassword,
      );
      return this.createSuccessResponse('Password changed successfully');
    } catch (error) {
      this.logger.error('Password change failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          error.message,
          'PASSWORD_CHANGE_ERROR',
          'CHANGE_FAILED',
        ),
      );
    }
  }
}
