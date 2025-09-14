import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UrlConfigService {
  constructor(private readonly configService: ConfigService) { }

  /**
    * Get the backend URL based on NODE_ENV
    * Production: Uses production domains
    * Development: Uses localhost with appropriate ports
    */
  getBackendUrl(): string {
    const backendUrl = this.configService.get<string>('BACKEND_URL');

    if (backendUrl) {
      return backendUrl;
    }

    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');

    if (nodeEnv === 'production') {
      // Use production default from environment
      const productionBackendUrl = this.configService.get<string>('PRODUCTION_BACKEND_URL', 'http://31.97.62.51:5555');
      return productionBackendUrl;
    }

    // Development defaults
    return 'http://localhost:5555';
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
      // Default production frontend from environment
      const productionFrontendUrl = this.configService.get<string>('PRODUCTION_FRONTEND_URL', 'http://31.97.62.51:4173');
      return productionFrontendUrl;
    }

    return 'http://localhost:4173'; // Development default
  }

  /**
    * Get base URL (alias for getBackendUrl for backward compatibility)
    */
  getBaseUrl(): string {
    return this.getBackendUrl();
  }

  /**
    * Get API URL (for internal API calls)
    */
  getApiUrl(): string {
    return this.getBackendUrl();
  }

  /**
   * Get CORS origins based on environment
   */
  getCorsOrigins(): string[] {
    const corsEnv = this.configService.get<string>('CORS_ORIGIN');

    if (corsEnv) {
      return corsEnv.split(',').map((origin) => origin.trim());
    }

    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');

    if (nodeEnv === 'production') {
      return [this.getFrontendUrl(), this.getBackendUrl()];
    }

    // Development origins
    return [
      this.getFrontendUrl(), // http://localhost:4173 (Vite preview)
      'http://localhost:4000', // Bash runner API
      'http://localhost:3000', // Alternative frontend
      'https://accounts.google.com', // Google OAuth
    ];
  }

  /**
   * Generate OAuth callback URL for a provider
   */
  getOAuthCallbackUrl(provider: string): string {
    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');

    // Use backend URL for all environments
    const backendUrl = this.getBackendUrl();
    return `${backendUrl}/api/auth/${provider}/callback`;
  }

  /**
    * Generate OAuth authorization URL
    */
  getOAuthAuthUrl(provider: string): string {
    const backendUrl = this.getBackendUrl();
    return `${backendUrl}/api/auth/${provider}`;
  }

  /**
    * Generate Swagger URL
    */
  getSwaggerUrl(): string {
    const backendUrl = this.getBackendUrl();
    return `${backendUrl}/api/docs`;
  }

  /**
   * Generate password reset URL
   */
  getPasswordResetUrl(token: string): string {
    const frontendUrl = this.getFrontendUrl();
    return `${frontendUrl}/reset-password?token=${token}`;
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
  getAuthRedirectUrl(
    success: boolean,
    params: Record<string, any> = {},
  ): string {
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
