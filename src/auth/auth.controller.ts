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
import { UrlConfigService } from '../config/url.config';
import { PrismaService } from '../database/prisma/prisma.service';
import { UsersService } from '../users/users.service';
import { AuthService } from './auth.service';
import { LoginWithBackupCodeDto } from './dto/backup-code.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ResendVerificationEmailDto } from './dto/resend-verification-email.dto';
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
          alreadyVerified: false,
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Email already verified',
    schema: {
      example: {
        success: true,
        message: 'Email is already verified',
        data: {
          user: {
            id: 'uuid',
            email: 'user@example.com',
            isEmailVerified: true,
          },
          alreadyVerified: true,
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
  @ApiResponse({
    status: 200,
    description: 'Verification email sent successfully',
    schema: {
      example: {
        success: true,
        message: 'Verification email sent successfully',
        data: null,
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Email already verified or invalid email',
    schema: {
      example: {
        success: false,
        message: 'Email is already verified',
        error: 'BAD_REQUEST',
        code: 'EMAIL_ALREADY_VERIFIED',
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
    schema: {
      example: {
        success: false,
        message: 'User not found',
        error: 'NOT_FOUND',
        code: 'USER_NOT_FOUND',
      },
    },
  })
  async resendVerificationEmail(
    @Body() dto: ResendVerificationEmailDto,
  ): Promise<ApiResponse> {
    try {
      await this.authService.resendVerificationEmail(dto.email);
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

      this.logger.log(`✅ Google OAuth successful for: ${result.user.email}`);

      const redirectUrl = this.urlConfigService.getAuthRedirectUrl(true, {
        token: result.accessToken,
        refresh: result.refreshToken,
        user: JSON.stringify(result.user),
      });
      return res.redirect(redirectUrl);
    } catch (error) {
      this.logger.error('Google OAuth callback error:', error.message);

      const redirectUrl = this.urlConfigService.getAuthRedirectUrl(false, {
        error: 'oauth_failed',
        message: encodeURIComponent(error.message),
      });
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
    const baseUrl = this.urlConfigService.getBaseUrl();

    const config = {
      clientId: this.configService.get('GOOGLE_CLIENT_ID'),
      callbackUrl: this.urlConfigService.getOAuthCallbackUrl('google'),
      authUrl: this.urlConfigService.getOAuthAuthUrl('google'),
    };

    return this.createSuccessResponse(
      'Google OAuth configuration retrieved',
      config,
    );
  }

  // ========== GOOGLE GTM OAUTH (Google Tag Manager) ==========

  @Public()
  @Get('google-gtm')
  @ApiOperation({
    summary: 'Initiate Google GTM OAuth login',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirect to Google GTM OAuth',
  })
  @UseGuards(AuthGuard('google-gtm'))
  async googleGtmAuth() {
    // Passport handles redirect automatically
  }

  @Public()
  @Get('google-gtm/callback')
  @ApiOperation({
    summary: 'Google GTM OAuth callback handler',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirect to frontend with GTM permission token',
  })
  @UseGuards(AuthGuard('google-gtm'))
  async googleGtmAuthRedirect(@Req() req: Request, @Res() res: Response) {
    try {
      // req.user is already validated by Google GTM OAuth strategy
      const oauthUser = req.user as any;
      if (!oauthUser || !oauthUser.id) {
        throw new UnauthorizedException('Invalid user from OAuth');
      }

      // For OAuth callbacks, we don't want to trigger 2FA again
      // So we generate tokens directly using the validated user
      const user = await this.usersService.findById(oauthUser.id);

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Generate JWT tokens (access and refresh) directly
      const tokens = await this.authService.generateTokens(
        user.id,
        user.email,
        user.roles,
        false, // rememberMe
      );

      // Get Google access token for API calls
      const googleTokens = await this.authService.getGoogleTokens(user.id);

      // Generate GTM permission token for accessing GTM APIs
      const gtmPermissionToken =
        await this.authService.generateGTMPermissionToken(user.id);

      this.logger.log(`✅ Google GTM OAuth successful for: ${user.email}`);

      // Get primary provider for user info
      const primaryProvider = await this.prisma.authProvider.findFirst({
        where: { userId: user.id, isPrimary: true },
        select: { provider: true },
      });

      // Simplify callback to return only essential tokens
      // For GTM flow, permissionToken is sufficient for API access
      const redirectUrl = this.urlConfigService.getAuthRedirectUrl(true, {
        // Primary JWT token (with GTM permissions - can use for general auth if needed)
        token: tokens.accessToken,
        // GTM-specific permission token (preferred for GTM endpoints)
        permissionToken: gtmPermissionToken.permissionToken,
        // User info for frontend state management
        user: JSON.stringify({
          id: user.id,
          email: user.email,
          name: user.name,
          avatar: user.avatar,
          provider: primaryProvider?.provider || 'google',
          isEmailVerified: user.isEmailVerified,
          isTwoFactorEnabled: user.isTwoFactorEnabled,
        }),
      });
      return res.redirect(redirectUrl);
    } catch (error) {
      this.logger.error('Google GTM OAuth callback error:', error.message);

      const redirectUrl = this.urlConfigService.getAuthRedirectUrl(false, {
        error: 'oauth_failed',
        message: encodeURIComponent(error.message),
      });
      return res.redirect(redirectUrl);
    }
  }

  @Public()
  @Get('google-gtm/config')
  @ApiOperation({
    summary: 'Get Google GTM OAuth configuration',
  })
  @ApiResponse({
    status: 200,
    description: 'Google GTM OAuth configuration',
    schema: {
      example: {
        success: true,
        message: 'Google GTM OAuth configuration retrieved',
        data: {
          clientId: 'google-client-id',
          callbackUrl: 'http://localhost:5555/api/auth/google-gtm/callback',
          authUrl: 'http://localhost:5555/api/auth/google-gtm',
          scopes: [
            'https://www.googleapis.com/auth/tagmanager.readonly',
            'https://www.googleapis.com/auth/tagmanager.manage.accounts',
            'https://www.googleapis.com/auth/tagmanager.edit.containers',
            'https://www.googleapis.com/auth/tagmanager.edit.containerversions',
            'https://www.googleapis.com/auth/tagmanager.publish',
          ],
        },
      },
    },
  })
  getGoogleGtmConfig(): ApiResponse {
    const baseUrl = this.urlConfigService.getBaseUrl();

    const config = {
      clientId: this.configService.get('GOOGLE_GTM_CLIENT_ID'),
      callbackUrl: this.urlConfigService.getOAuthCallbackUrl('google-gtm'),
      authUrl: this.urlConfigService.getOAuthAuthUrl('google-gtm'),
      scopes: [
        'https://www.googleapis.com/auth/tagmanager.readonly',
        'https://www.googleapis.com/auth/tagmanager.manage.accounts',
        'https://www.googleapis.com/auth/tagmanager.edit.containers',
        'https://www.googleapis.com/auth/tagmanager.edit.containerversions',
        'https://www.googleapis.com/auth/tagmanager.publish',
      ],
    };

    return this.createSuccessResponse(
      'Google GTM OAuth configuration retrieved',
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

      this.logger.log(`✅ Facebook OAuth successful for: ${result.user.email}`);

      const redirectUrl = this.urlConfigService.getAuthRedirectUrl(true, {
        token: result.accessToken,
        refresh: result.refreshToken,
        user: JSON.stringify(result.user),
      });
      return res.redirect(redirectUrl);
    } catch (error) {
      this.logger.error('Facebook OAuth callback error:', error.message);

      const redirectUrl = this.urlConfigService.getAuthRedirectUrl(false, {
        error: 'oauth_failed',
        message: encodeURIComponent(error.message),
      });
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
    const config = {
      appId: this.configService.get('FACEBOOK_APP_ID'),
      callbackUrl: this.urlConfigService.getOAuthCallbackUrl('facebook'),
      authUrl: this.urlConfigService.getOAuthAuthUrl('facebook'),
    };

    return this.createSuccessResponse(
      'Facebook OAuth configuration retrieved',
      config,
    );
  }

  // ========== GITHUB OAUTH ==========
  @Public()
  @Get('github')
  @ApiOperation({
    summary: 'Initiate GitHub OAuth login',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirect to GitHub OAuth',
  })
  @UseGuards(AuthGuard('github'))
  async githubAuth() {
    // Passport handles redirect automatically
  }

  @Public()
  @Get('github/callback')
  @ApiOperation({
    summary: 'GitHub OAuth callback handler',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirect to frontend with tokens',
  })
  @UseGuards(AuthGuard('github'))
  async githubAuthRedirect(@Req() req: Request, @Res() res: Response) {
    try {
      const result = await this.authService.githubLogin(req.user);

      this.logger.log(`✅ GitHub OAuth successful for: ${result.user.email}`);

      const redirectUrl = this.urlConfigService.getAuthRedirectUrl(true, {
        token: result.accessToken,
        refresh: result.refreshToken,
        user: JSON.stringify(result.user),
      });
      return res.redirect(redirectUrl);
    } catch (error) {
      this.logger.error('GitHub OAuth callback error:', error.message);

      const redirectUrl = this.urlConfigService.getAuthRedirectUrl(false, {
        error: 'oauth_failed',
        message: encodeURIComponent(error.message),
      });
      return res.redirect(redirectUrl);
    }
  }

  @Public()
  @Get('github/config')
  @ApiOperation({
    summary: 'Get GitHub OAuth configuration',
  })
  @ApiResponse({
    status: 200,
    description: 'GitHub OAuth configuration',
    schema: {
      example: {
        success: true,
        message: 'GitHub OAuth configuration retrieved',
        data: {
          clientId: 'github-client-id',
          callbackUrl: 'http://localhost:5555/api/auth/github/callback',
          authUrl: 'http://localhost:5555/api/auth/github',
        },
      },
    },
  })
  getGithubConfig(): ApiResponse {
    const config = {
      clientId: this.configService.get('GITHUB_CLIENT_ID'),
      callbackUrl: this.urlConfigService.getOAuthCallbackUrl('github'),
      authUrl: this.urlConfigService.getOAuthAuthUrl('github'),
    };

    return this.createSuccessResponse(
      'GitHub OAuth configuration retrieved',
      config,
    );
  }

  // ========== TWO-FACTOR AUTHENTICATION ==========

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('2fa/generate')
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
  @ApiBody({
    schema: {
      type: 'object',
      required: ['token', 'password'],
      properties: {
        token: {
          type: 'string',
          example: 'eyJhbGciOi...',
          description: 'Password reset token',
        },
        password: {
          type: 'string',
          example: 'newpassword123',
          description: 'New password',
          minLength: 6,
          maxLength: 100,
        },
      },
    },
  })
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
  @ApiBody({
    schema: {
      type: 'object',
      required: ['email', 'backupCode', 'tempToken'],
      properties: {
        email: {
          type: 'string',
          format: 'email',
          example: 'user@example.com',
          description: 'User email address',
        },
        backupCode: {
          type: 'string',
          example: 'ABCD1234',
          description: 'Backup code (8 characters alphanumeric)',
          minLength: 8,
          maxLength: 8,
          pattern: '^[A-Z0-9]{8}$',
        },
        tempToken: {
          type: 'string',
          example: 'eyJhbGciOi...',
          description: 'Temporary token from /login',
        },
      },
    },
  })
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

  // ========== PROVIDER MANAGEMENT ==========

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('providers')
  @ApiOperation({
    summary: 'Get all linked authentication providers for current user',
  })
  @ApiResponse({
    status: 200,
    description: 'Providers retrieved successfully',
    schema: {
      example: {
        success: true,
        message: 'Providers retrieved successfully',
        data: [
          {
            id: 'provider-id',
            provider: 'GOOGLE',
            email: 'user@gmail.com',
            isPrimary: true,
            linkedAt: '2023-01-01T00:00:00.000Z',
            lastUsedAt: '2023-01-01T00:00:00.000Z',
          },
        ],
      },
    },
  })
  async getUserProviders(@User('id') userId: string): Promise<ApiResponse> {
    try {
      const providers = await this.authService.getUserProviders(userId);
      return this.createSuccessResponse(
        'Providers retrieved successfully',
        providers,
      );
    } catch (error) {
      this.logger.error('Failed to get user providers:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to get providers',
          'PROVIDER_ERROR',
          'GET_PROVIDERS_FAILED',
        ),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Post('providers/unlink')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Unlink an authentication provider' })
  @ApiBody({
    schema: {
      example: {
        provider: 'google',
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Provider unlinked successfully',
    schema: {
      example: {
        success: true,
        message: 'Provider unlinked successfully',
        data: null,
      },
    },
  })
  async unlinkProvider(
    @User('id') userId: string,
    @Body() body: { provider: string },
  ): Promise<ApiResponse> {
    try {
      await this.authService.unlinkProvider(userId, body.provider);
      return this.createSuccessResponse('Provider unlinked successfully');
    } catch (error) {
      this.logger.error('Provider unlinking failed:', error.message);

      if (error instanceof NotFoundException) {
        throw new NotFoundException(
          this.createErrorResponse(
            error.message,
            'PROVIDER_ERROR',
            'PROVIDER_NOT_FOUND',
          ),
        );
      }

      if (error instanceof BadRequestException) {
        throw new BadRequestException(
          this.createErrorResponse(
            error.message,
            'PROVIDER_ERROR',
            'UNLINK_FAILED',
          ),
        );
      }

      throw new BadRequestException(
        this.createErrorResponse(
          'Failed to unlink provider',
          'PROVIDER_ERROR',
          'UNLINK_PROVIDER_FAILED',
        ),
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Post('providers/set-primary')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Set primary authentication provider' })
  @ApiBody({
    schema: {
      example: {
        provider: 'google',
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Primary provider set successfully',
    schema: {
      example: {
        success: true,
        message: 'Primary provider set successfully',
        data: null,
      },
    },
  })
  async setPrimaryProvider(
    @User('id') userId: string,
    @Body() body: { provider: string },
  ): Promise<ApiResponse> {
    try {
      const providerEnum = this.mapStringToProviderEnum(body.provider);
      await this.authService.setPrimaryProvider(userId, providerEnum);
      return this.createSuccessResponse('Primary provider set successfully');
    } catch (error) {
      this.logger.error('Setting primary provider failed:', error.message);
      throw new BadRequestException(
        this.createErrorResponse(
          error.message,
          'PROVIDER_ERROR',
          'SET_PRIMARY_FAILED',
        ),
      );
    }
  }

  // ========== GOOGLE GTM PERMISSION TOKEN ==========

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @Get('google-gtm/permission-token')
  @ApiOperation({
    summary: 'Generate Google Tag Manager permission token',
    description:
      'Creates a short-lived permission token for accessing Google Tag Manager APIs. This token should be used in the Authorization header when calling GTM endpoints.',
  })
  @ApiResponse({
    status: 200,
    description: 'Permission token generated successfully',
    schema: {
      example: {
        success: true,
        message: 'GTM permission token generated successfully',
        data: {
          permissionToken: 'jwt.token.here',
          expiresIn: 900000,
          issuedAt: 1693963267000,
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Google authentication required',
    schema: {
      example: {
        success: false,
        message: 'Google authentication required for GTM access',
        error: 'UNAUTHORIZED',
        code: 'GOOGLE_AUTH_REQUIRED',
      },
    },
  })
  async getGTMPermissionToken(
    @User('id') userId: string,
  ): Promise<ApiResponse> {
    try {
      const tokenData =
        await this.authService.generateGTMPermissionToken(userId);
      return this.createSuccessResponse(
        'GTM permission token generated successfully',
        tokenData,
      );
    } catch (error) {
      this.logger.error(
        'GTM permission token generation failed:',
        error.message,
      );
      throw new BadRequestException(
        this.createErrorResponse(
          error.message,
          'AUTH_ERROR',
          'PERMISSION_TOKEN_FAILED',
        ),
      );
    }
  }

  private mapStringToProviderEnum(provider: string): any {
    const providerMap: { [key: string]: any } = {
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
}
