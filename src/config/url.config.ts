import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UrlConfigService {
  constructor(private readonly configService: ConfigService) {}

  /**
   * Get the base URL based on NODE_ENV
   * Production: Uses production domains
   * Development: Uses localhost with appropriate ports
   */
  getBaseUrl(): string {
    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');

    if (nodeEnv === 'production') {
      // Use environment variable or fallback to your production domain
      return this.configService.get<string>('BASE_URL', 'https://your-domain.com');
    }

    // Development defaults
    const port = this.configService.get<string>('PORT', '5555');
    return `http://localhost:${port}`;
  }

  /**
   * Get frontend URL
   */
  getFrontendUrl(): string {
    const frontendUrl = this.configService.get<string>('FRONTEND_URL');

    if (frontendUrl) {
      return frontendUrl;
    }

    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');

    if (nodeEnv === 'production') {
      return this.configService.get<string>('FRONTEND_URL_PROD', 'https://your-frontend.com');
    }

    return 'http://localhost:5173'; // Development default
  }

  /**
   * Get API URL (for internal API calls)
   */
  getApiUrl(): string {
    return this.configService.get<string>('API_URL', this.getBaseUrl());
  }

  /**
   * Get CORS origins based on environment
   */
  getCorsOrigins(): string[] {
    const corsEnv = this.configService.get<string>('CORS_ORIGIN');

    if (corsEnv) {
      return corsEnv.split(',').map(origin => origin.trim());
    }

    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');

    if (nodeEnv === 'production') {
      return [
        this.getFrontendUrl(),
        this.getBaseUrl()
      ];
    }

    // Development origins
    return [
      this.getFrontendUrl(), // http://localhost:5173 (Vite)
      'http://localhost:4000', // Bash runner API
      'http://localhost:3000', // Alternative frontend
      'http://localhost:4173', // Vite preview
      'https://accounts.google.com' // Google OAuth
    ];
  }

  /**
   * Generate OAuth callback URL for a provider
   */
  getOAuthCallbackUrl(provider: string): string {
    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');

    // For development, use Swagger docs URL for auto session management
    if (nodeEnv === 'development') {
      const swaggerUrl = this.getSwaggerUrl();
      // Remove /docs suffix to get base swagger URL
      return `${this.getBaseUrl()}/api/auth/${provider}/callback`;
    }

    // Production uses actual callback endpoint
    const baseUrl = this.getBaseUrl();
    return `${baseUrl}/api/auth/${provider}/callback`;
  }

  /**
   * Generate OAuth authorization URL
   */
  getOAuthAuthUrl(provider: string): string {
    const baseUrl = this.getBaseUrl();
    return `${baseUrl}/api/auth/${provider}`;
  }

  /**
   * Generate Swagger URL
   */
  getSwaggerUrl(): string {
    const baseUrl = this.getBaseUrl();
    return `${baseUrl}/api/docs`;
  }

  /**
   * Generate password reset URL
   */
  getPasswordResetUrl(token: string): string {
    const frontendUrl = this.getFrontendUrl();
    return `${frontendUrl}/auth/reset-password?token=${token}`;
  }

  /**
   * Generate email verification URL
   */
  getEmailVerificationUrl(token: string): string {
    const frontendUrl = this.getFrontendUrl();
    return `${frontendUrl}/api/auth/verify-email?token=${token}`;
  }

  /**
   * Generate auth redirect URL
   */
  getAuthRedirectUrl(success: boolean, params: Record<string, any> = {}): string {
    const frontendUrl = this.getFrontendUrl();
    const basePath = `${frontendUrl}/auth/callback`;

    const searchParams = new URLSearchParams();
    searchParams.append('success', success.toString());

    Object.entries(params).forEach(([key, value]) => {
      searchParams.append(key, String(value));
    });

    return `${basePath}?${searchParams.toString()}`;
  }
}