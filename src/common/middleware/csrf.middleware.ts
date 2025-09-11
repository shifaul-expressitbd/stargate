import { Injectable, NestMiddleware } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { NextFunction, Request, Response } from 'express';
const csurf = require('csurf');

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private csrfProtection: any;

  constructor(
    private reflector: Reflector,
    private configService: ConfigService,
  ) {
    this.csrfProtection = csurf({
      cookie: {
        key: 'XSRF-TOKEN',
        httpOnly: false, // Allow frontend to read the cookie
        secure: this.configService.get<string>('NODE_ENV') === 'production',
        sameSite: 'strict',
      },
      value: (req: Request) => {
        // Support both header and body
        return (
          (req.headers['x-xsrf-token'] as string) ||
          (req.headers['x-csrf-token'] as string) ||
          req.body._csrf
        );
      },
    });
  }

  use(req: Request, res: Response, next: NextFunction): void {
    // Skip CSRF for public routes (login, register, health, csrf-token)
    const publicPaths = [
      '/api/auth/login',
      '/api/auth/register',
      '/api/health',
      '/api/csrf-token',
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
    this.csrfProtection(req, res, (err?: any) => {
      if (err) {
        // Handle CSRF error
        return res.status(403).json({
          statusCode: 403,
          message: 'Invalid CSRF token',
          error: 'Forbidden',
        });
      }
      next();
    });
  }
}
