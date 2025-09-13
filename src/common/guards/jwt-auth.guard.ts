import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const handler = context.getHandler();
    const controller = context.getClass();

    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      handler,
      controller,
    ]);

    console.log(`🔍 JWT Guard Check - Controller: ${controller.name}, Handler: ${handler.name}, isPublic: ${isPublic}`);
    console.log(`🔍 Authorization Header: ${request.headers.authorization ? 'Present' : 'Missing'}`);
    console.log(`🔍 Request Method: ${request.method}, URL: ${request.url}`);

    if (isPublic) {
      console.log(`✅ Endpoint is public, bypassing JWT validation`);
      return true;
    }

    console.log(`🔒 Endpoint requires authentication, proceeding with JWT validation`);
    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    if (err || !user) {
      throw (
        err || new UnauthorizedException('Access token is invalid or expired')
      );
    }
    return user;
  }
}
