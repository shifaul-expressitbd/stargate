import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class PermissionTokenGuard extends AuthGuard('jwt') {
  constructor() {
    super();
  }

  canActivate(context: any) {
    // First, let the parent JWT guard validate the token
    const isValidJwt = super.canActivate(context);

    if (!isValidJwt) {
      return false;
    }

    // Get the validated user from JWT
    const request = context.switchToHttp().getRequest();

    // Additional check: verify it's a GTM permission token
    if (!request.user || request.user.type !== 'gtm-permission') {
      return false;
    }

    return true;
  }

  handleRequest(err: any, user: any, info: any, context: any) {
    if (err) {
      return null;
    }

    if (!user) {
      return null;
    }

    // Additional validation for permission tokens
    if (!user.type || user.type !== 'gtm-permission') {
      return null;
    }

    return user;
  }
}