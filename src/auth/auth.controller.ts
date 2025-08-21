import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
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
import { Public } from '../common/decorators/public.decorator';
import { User } from '../common/decorators/user.decorator';
import { UsersService } from '../users/users.service';
import { AuthService } from './auth.service';
import { LoginWithBackupCodeDto } from './dto/backup-code.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ForgotPasswordDto, ResetPasswordDto } from './dto/reset-password.dto';
import {
  EnableTwoFactorDto,
  LoginWithTwoFactorDto,
  VerifyTwoFactorDto,
} from './dto/two-factor.dto';

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
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
  ) { }

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
  @ApiBody({ type: RegisterDto })
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
  @ApiResponse({
    status: 400,
    description: 'Bad Request',
    schema: {
      example: {
        success: false,
        message: 'Password must be at least 8 characters long',
        error: 'VALIDATION_ERROR',
        code: 'PASSWORD_TOO_SHORT',
      },
    },
  })
  @ApiResponse({
    status: 409,
    description: 'User already exists',
    schema: {
      example: {
        success: false,
        message: 'User already exists',
        error: 'CONFLICT',
        code: 'USER_EXISTS',
      },
    },
  })
  async register(@Body() registerDto: RegisterDto): Promise<ApiResponse> {
    try {
      const result = await this.authService.register(registerDto);
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
  @UseGuards(AuthGuard('local'))
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiBody({ type: LoginDto })
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
  @ApiResponse({
    status: 401,
    description: 'Invalid credentials',
    schema: {
      example: {
        success: false,
        message: 'Invalid email or password',
        error: 'UNAUTHORIZED',
        code: 'INVALID_CREDENTIALS',
      },
    },
  })
  @ApiResponse({
    status: 403,
    description: 'Email not verified',
    schema: {
      example: {
        success: false,
        message: 'Please verify your email before logging in',
        error: 'FORBIDDEN',
        code: 'EMAIL_NOT_VERIFIED',
      },
    },
  })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
  ): Promise<ApiResponse> {
    try {
      const result = await this.authService.login(
        req.user,
        loginDto.rememberMe,
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
  @Get('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('refresh-token')
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
  @ApiResponse({
    status: 401,
    description: 'Invalid refresh token',
    schema: {
      example: {
        success: false,
        message: 'Invalid or expired refresh token',
        error: 'UNAUTHORIZED',
        code: 'INVALID_REFRESH_TOKEN',
      },
    },
  })
  async refresh(
    @User() user: any,
    @Query('rememberMe') rememberMe?: string,
  ): Promise<ApiResponse> {
    try {
      const shouldRememberMe = rememberMe?.trim().toLowerCase() === 'true';
      const result = await this.authService.refreshToken(
        user.sub,
        user.email,
        shouldRememberMe,
      );

      return this.createSuccessResponse('Token refreshed successfully', result);
    } catch (error) {
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
          redirectUrl: 'https://frontend.com/auth/success',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid or expired token',
    schema: {
      example: {
        success: false,
        message: 'Invalid or expired verification token',
        error: 'BAD_REQUEST',
        code: 'INVALID_TOKEN',
      },
    },
  })
  async verifyEmail(@Query('token') token: string, @Res() res: Response) {
    try {
      if (!token) {
        throw new BadRequestException('Token is required');
      }

      const user = await this.usersService.findByVerificationToken(token);
      if (!user) {
        throw new BadRequestException('Invalid or expired verification token');
      }

      const updatedUser = await this.usersService.markEmailAsVerified(user.id);
      this.logger.log(`✅ Email verified for user: ${updatedUser.email}`);

      const frontendUrl = this.configService.get(
        'FRONTEND_URL',
        'http://localhost:5173',
      );
      const redirectUrl = `${frontendUrl}/auth/verify-email?success=true`;

      const response = this.createSuccessResponse(
        'Email verified successfully',
        {
          user: {
            id: updatedUser.id,
            email: updatedUser.email,
            isEmailVerified: updatedUser.isEmailVerified,
          },
          redirectUrl,
        },
      );

      const accept = res.req.headers.accept || '';
      if (accept.includes('application/json')) {
        return res.json(response);
      } else {
        return res.redirect(redirectUrl);
      }
    } catch (error) {
      this.logger.error('Email verification error:', error.message);

      const frontendUrl = this.configService.get(
        'FRONTEND_URL',
        'http://localhost:5173',
      );
      const errorResponse = this.createErrorResponse(
        error.message,
        'VERIFICATION_FAILED',
        'INVALID_TOKEN',
      );

      const accept = res.req.headers.accept || '';
      if (accept.includes('application/json')) {
        return res.status(400).json(errorResponse);
      } else {
        const redirectUrl = `${frontendUrl}/auth/verify-email?error=true&message=${encodeURIComponent(error.message)}`;
        return res.redirect(redirectUrl);
      }
    }
  }

  // ========== GOOGLE OAUTH ==========
  @Public()
  @Get('google')
  @ApiOperation({
    summary: 'Initiate Google OAuth login',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirect to Google OAuth',
  })
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Passport handles redirect automatically
  }

  @Public()
  @Get('google/callback')
  @ApiOperation({
    summary: 'Google OAuth callback handler',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirect to frontend with tokens',
  })
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req: Request, @Res() res: Response) {
    try {
      const result = await this.authService.googleLogin(req.user);
      const frontendUrl = this.configService.get(
        'FRONTEND_URL',
        'http://localhost:5173',
      );

      this.logger.log(`✅ Google OAuth successful for: ${result.user.email}`);

      const redirectUrl = `${frontendUrl}/auth/callback?success=true&token=${result.accessToken}&refresh=${result.refreshToken}&user=${encodeURIComponent(JSON.stringify(result.user))}`;
      return res.redirect(redirectUrl);
    } catch (error) {
      this.logger.error('Google OAuth callback error:', error.message);
      const frontendUrl = this.configService.get(
        'FRONTEND_URL',
        'http://localhost:5173',
      );

      const redirectUrl = `${frontendUrl}/auth/callback?error=oauth_failed&message=${encodeURIComponent(error.message)}`;
      return res.redirect(redirectUrl);
    }
  }

  @Public()
  @Get('google/config')
  @ApiOperation({
    summary: 'Get Google OAuth configuration',
  })
  @ApiResponse({
    status: 200,
    description: 'Google OAuth configuration',
    schema: {
      example: {
        success: true,
        message: 'Google OAuth configuration retrieved',
        data: {
          clientId: 'google-client-id',
          callbackUrl: 'http://localhost:5555/api/auth/google/callback',
          authUrl: 'http://localhost:5555/api/auth/google',
        },
      },
    },
  })
  getGoogleConfig(): ApiResponse {
    const baseUrl =
      process.env.NODE_ENV === 'production'
        ? 'https://your-domain.com'
        : 'http://localhost:5555';

    const config = {
      clientId: this.configService.get('GOOGLE_CLIENT_ID'),
      callbackUrl: `${baseUrl}/api/auth/google/callback`,
      authUrl: `${baseUrl}/api/auth/google`,
    };

    return this.createSuccessResponse(
      'Google OAuth configuration retrieved',
      config,
    );
  }


  // ========== FACEBOOK OAUTH ==========
  @Public()
  @Get('facebook')
  @ApiOperation({
    summary: 'Initiate Facebook OAuth login',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirect to Facebook OAuth',
  })
  @UseGuards(AuthGuard('facebook'))
  async facebookAuth() {
    // Passport handles redirect automatically
  }

  @Public()
  @Get('facebook/callback')
  @ApiOperation({
    summary: 'Facebook OAuth callback handler',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirect to frontend with tokens',
  })
  @UseGuards(AuthGuard('facebook'))
  async facebookAuthRedirect(@Req() req: Request, @Res() res: Response) {
    try {
      const result = await this.authService.facebookLogin(req.user);
      const frontendUrl = this.configService.get(
        'FRONTEND_URL',
        'http://localhost:5173',
      );

      this.logger.log(`✅ Facebook OAuth successful for: ${result.user.email}`);

      const redirectUrl = `${frontendUrl}/auth/callback?success=true&token=${result.accessToken}&refresh=${result.refreshToken}&user=${encodeURIComponent(JSON.stringify(result.user))}`;
      return res.redirect(redirectUrl);
    } catch (error) {
      this.logger.error('Facebook OAuth callback error:', error.message);
      const frontendUrl = this.configService.get(
        'FRONTEND_URL',
        'http://localhost:5173',
      );

      const redirectUrl = `${frontendUrl}/auth/callback?error=oauth_failed&message=${encodeURIComponent(error.message)}`;
      return res.redirect(redirectUrl);
    }
  }

  @Public()
  @Get('facebook/config')
  @ApiOperation({
    summary: 'Get Facebook OAuth configuration',
  })
  @ApiResponse({
    status: 200,
    description: 'Facebook OAuth configuration',
    schema: {
      example: {
        success: true,
        message: 'Facebook OAuth configuration retrieved',
        data: {
          appId: 'facebook-app-id',
          callbackUrl: 'http://localhost:5555/api/auth/facebook/callback',
          authUrl: 'http://localhost:5555/api/auth/facebook',
        },
      },
    },
  })
  getFacebookConfig(): ApiResponse {
    const baseUrl = process.env.NODE_ENV === 'production'
      ? 'https://your-domain.com'
      : 'http://localhost:5555';

    const config = {
      appId: this.configService.get('FACEBOOK_APP_ID'),
      callbackUrl: `${baseUrl}/api/auth/facebook/callback`,
      authUrl: `${baseUrl}/api/auth/facebook`,
    };

    return this.createSuccessResponse(
      'Facebook OAuth configuration retrieved',
      config,
    );
  }
  
  // ========== TWO-FACTOR AUTHENTICATION ==========

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Post('2fa/generate')
  @ApiOperation({ summary: 'Generate 2FA secret for current user' })
  @ApiResponse({
    status: 200,
    description: '2FA secret generated',
    schema: {
      example: {
        success: true,
        message: '2FA secret generated successfully',
        data: {
          secret: 'base32-secret',
          qrCodeUrl: 'data:image/png;base64,...',
          manualEntryKey: 'base32-secret',
          otpAuthUrl: 'otpauth://totp/...',
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
    schema: {
      example: {
        success: false,
        message: 'Authentication required',
        error: 'UNAUTHORIZED',
        code: 'AUTH_REQUIRED',
      },
    },
  })
  async generateTwoFactorSecret(
    @User('id') userId: string,
  ): Promise<ApiResponse> {
    try {
      const result = await this.authService.generateTwoFactorSecret(userId);
      return this.createSuccessResponse(
        '2FA secret generated successfully',
        result,
      );
    } catch (error) {
      this.logger.error('2FA secret generation failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to generate 2FA secret',
          '2FA_ERROR',
          'GENERATION_FAILED',
        ),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Post('2fa/verify')
  @ApiOperation({ summary: 'Verify a 2FA TOTP code' })
  @ApiResponse({
    status: 200,
    description: 'Code is valid',
    schema: {
      example: {
        success: true,
        message: '2FA code is valid',
        data: { valid: true },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid 2FA code',
    schema: {
      example: {
        success: false,
        message: 'Invalid 2FA code',
        error: 'UNAUTHORIZED',
        code: 'INVALID_2FA_CODE',
      },
    },
  })
  async verifyTwoFactor(
    @User('id') userId: string,
    @Body() dto: VerifyTwoFactorDto,
  ): Promise<ApiResponse> {
    try {
      const isValid = await this.authService.verifyTwoFactorCode(
        userId,
        dto.code,
      );
      if (!isValid) {
        throw new UnauthorizedException('Invalid 2FA code');
      }
      return this.createSuccessResponse('2FA code is valid', { valid: true });
    } catch (error) {
      this.logger.error('2FA verification failed:', error.message);
      throw new UnauthorizedException(
        this.createErrorResponse(error.message, '2FA_ERROR', 'INVALID_CODE'),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Throttle({ default: { limit: 3, ttl: 300 } })
  @Post('2fa/enable')
  @ApiOperation({ summary: 'Enable two-factor authentication' })
  @ApiResponse({
    status: 200,
    description: '2FA enabled successfully',
    schema: {
      example: {
        success: true,
        message: '2FA enabled successfully',
        data: {
          success: true,
          backupCodes: ['BACKUP1', 'BACKUP2'],
        },
      },
    },
  })
  async enableTwoFactor(
    @User('id') userId: string,
    @Body() dto: EnableTwoFactorDto,
  ): Promise<ApiResponse> {
    try {
      const result = await this.authService.enableTwoFactor(
        userId,
        dto.code,
        dto.skipBackup,
      );
      return this.createSuccessResponse('2FA enabled successfully', result);
    } catch (error) {
      this.logger.error('2FA enable failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(error.message, '2FA_ERROR', 'ENABLE_FAILED'),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Throttle({ default: { limit: 3, ttl: 300 } })
  @Post('2fa/disable')
  @ApiOperation({ summary: 'Disable two-factor authentication' })
  @ApiResponse({
    status: 200,
    description: '2FA disabled successfully',
    schema: {
      example: {
        success: true,
        message: '2FA disabled successfully',
        data: { success: true },
      },
    },
  })
  async disableTwoFactor(
    @User('id') userId: string,
    @Body() dto: EnableTwoFactorDto,
  ): Promise<ApiResponse> {
    try {
      const result = await this.authService.disableTwoFactor(userId, dto.code);
      return this.createSuccessResponse('2FA disabled successfully', result);
    } catch (error) {
      this.logger.error('2FA disable failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(error.message, '2FA_ERROR', 'DISABLE_FAILED'),
      );
    }
  }

  @Public()
  @Throttle({ default: { limit: 5, ttl: 300 } })
  @Post('2fa/login/totp')
  @ApiOperation({ summary: 'Login using 2FA code' })
  @ApiResponse({
    status: 200,
    description: 'Login successful with 2FA',
    schema: {
      example: {
        success: true,
        message: 'Two-factor authentication successful',
        data: {
          user: {
            id: 'uuid',
            email: 'user@example.com',
            name: 'John Doe',
            avatar: 'https://example.com/avatar.jpg',
            provider: 'local',
            isEmailVerified: true,
            isTwoFactorEnabled: true,
          },
          accessToken: 'jwt-token',
          refreshToken: 'refresh-token',
        },
      },
    },
  })
  async loginWithTwoFactor(
    @Body() dto: LoginWithTwoFactorDto,
  ): Promise<ApiResponse> {
    try {
      const result = await this.authService.loginWithTwoFactor(dto);
      return this.createSuccessResponse(
        'Two-factor authentication successful',
        result,
      );
    } catch (error) {
      this.logger.error('2FA login failed:', error.message);
      throw new UnauthorizedException(
        this.createErrorResponse(error.message, '2FA_ERROR', 'LOGIN_FAILED'),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('2fa/status')
  @ApiOperation({ summary: 'Check 2FA status for current user' })
  @ApiResponse({
    status: 200,
    description: '2FA status retrieved',
    schema: {
      example: {
        success: true,
        message: '2FA status retrieved successfully',
        data: {
          isEnabled: true,
          hasSecret: true,
        },
      },
    },
  })
  async getTwoFactorStatus(@User('id') userId: string): Promise<ApiResponse> {
    try {
      const result = await this.authService.getTwoFactorStatus(userId);
      return this.createSuccessResponse(
        '2FA status retrieved successfully',
        result,
      );
    } catch (error) {
      this.logger.error('2FA status check failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to get 2FA status',
          '2FA_ERROR',
          'STATUS_CHECK_FAILED',
        ),
      );
    }
  }

  // ========== LOGOUT ==========
  @Post('logout')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Logout current user' })
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
    this.logger.log(`User logged out: ${user.email}`);
    return this.createSuccessResponse('Logged out successfully');
  }

  // ========== PASSWORD RESET ==========
  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.ACCEPTED)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({ summary: 'Request password reset email' })
  @ApiResponse({
    status: 202,
    description: 'Password reset email sent',
    schema: {
      example: {
        success: true,
        message: 'Password reset email sent successfully',
        data: null,
      },
    },
  })
  async forgotPassword(
    @Body() { email }: ForgotPasswordDto,
  ): Promise<ApiResponse> {
    try {
      const result = await this.authService.requestPasswordReset(email);
      // If result is void, use a generic success message
      return this.createSuccessResponse(
        'Password reset email sent successfully',
      );
    } catch (error) {
      this.logger.error('Password reset request failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to send password reset email',
          'PASSWORD_RESET_ERROR',
          'RESET_REQUEST_FAILED',
        ),
      );
    }
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password using token' })
  @ApiResponse({
    status: 200,
    description: 'Password reset successful',
    schema: {
      example: {
        success: true,
        message: 'Password reset successfully',
        data: null,
      },
    },
  })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<ApiResponse> {
    try {
      const result = await this.authService.resetPassword(
        resetPasswordDto.token,
        resetPasswordDto.password,
      );
      // If result is void, use a generic success message
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

  // ========== BACKUP CODE LOGIN ==========
  @Public()
  @Post('2fa/login/backup-code')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @ApiOperation({ summary: 'Login using a backup code (for 2FA)' })
  @ApiBody({ type: LoginWithBackupCodeDto })
  @ApiResponse({
    status: 200,
    description: 'Login successful with backup code',
    schema: {
      example: {
        success: true,
        message: 'Login successful with backup code',
        data: {
          user: {
            id: 'uuid',
            email: 'user@example.com',
            name: 'John Doe',
            avatar: 'https://example.com/avatar.jpg',
            provider: 'local',
            isEmailVerified: true,
            isTwoFactorEnabled: true,
          },
          accessToken: 'jwt-token',
          refreshToken: 'refresh-token',
          remainingBackupCodes: 7,
          message: 'Login successful with backup code',
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid backup code or token',
    schema: {
      example: {
        success: false,
        message: 'Invalid backup code',
        error: 'UNAUTHORIZED',
        code: 'INVALID_BACKUP_CODE',
      },
    },
  })
  async loginWithBackupCode(
    @Body() loginWithBackupCodeDto: LoginWithBackupCodeDto,
  ): Promise<ApiResponse> {
    try {
      const result = await this.authService.loginWithBackupCode(
        loginWithBackupCodeDto.tempToken,
        loginWithBackupCodeDto.backupCode,
      );

      // Get updated user to check remaining backup codes
      const user = await this.usersService.findByEmail(result.user.email);

      // Use a generic success message instead of result.message
      return this.createSuccessResponse('Login successful with backup code', {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        remainingBackupCodes: user?.backupCodes?.length || 0,
        message: 'Login successful with backup code',
      });
    } catch (error) {
      this.logger.error('Backup code login failed:', error.message);

      if (error instanceof UnauthorizedException) {
        throw new UnauthorizedException(
          this.createErrorResponse(
            error.message,
            'UNAUTHORIZED',
            'INVALID_BACKUP_CODE',
          ),
        );
      }

      throw new BadRequestException(
        this.createErrorResponse(
          'Backup code login failed',
          'AUTH_ERROR',
          'BACKUP_CODE_LOGIN_FAILED',
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
  @ApiResponse({
    status: 200,
    description: 'Password changed successfully',
    schema: {
      example: {
        success: true,
        message: 'Password changed successfully',
        data: null,
      },
    },
  })
  async changePassword(
    @User('id') userId: string,
    @Body() changePasswordDto: ChangePasswordDto,
  ): Promise<ApiResponse> {
    try {
      const result = await this.authService.changePassword(
        userId,
        changePasswordDto.currentPassword,
        changePasswordDto.newPassword,
      );
      // If result is void, use a generic success message
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
