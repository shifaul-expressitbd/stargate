import { Injectable, NestMiddleware } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { doubleCsrf } from 'csrf-csrf';
import { NextFunction, Request, Response } from 'express';

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private csrfProtection: any;
  private generateCsrfToken: any;
  private secret: string;

  constructor(private configService: ConfigService) {
    this.secret = this.configService.get<string>(
      'CSRF_SECRET',
      'super-secret-csrf-key',
    );

    const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
      getSecret: () => this.secret,
      getSessionIdentifier: (req: Request) => req.ip || 'default-session',
      cookieName: 'csrf-token',
      cookieOptions: {
        httpOnly: false,
        secure: this.configService.get<string>('NODE_ENV') === 'production',
        sameSite: 'strict',
      },
    });

    this.csrfProtection = doubleCsrfProtection;
    this.generateCsrfToken = generateCsrfToken;
  }

  use(req: Request, res: Response, next: NextFunction): void {
    // Handle CSRF token generation for the token endpoint
    if (req.path === '/api/csrf-token') {
      const token = this.generateCsrfToken(req, res);
      // Set the token in a cookie
      res.cookie('csrf-token', token, {
        httpOnly: false,
        secure: this.configService.get<string>('NODE_ENV') === 'production',
        sameSite: 'strict',
      });
      return next();
    }

    // Skip CSRF for other public routes
    const publicPaths = [
      '/api/auth/login',
      '/api/auth/register',
      '/api/health',
      '/api',
    ];
    if (
      publicPaths.some(
        (path) => req.path === path || req.path.startsWith(path + '/'),
      )
    ) {
      return next();
    }

    // Apply CSRF protection for state-changing operations
    this.csrfProtection(req, res, next);
  }

  // Token generation is handled by the middleware automatically
  // The token is set in a cookie named 'csrf-token'
}
