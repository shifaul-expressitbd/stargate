// src/common/guards/impersonation.guard.ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';

@Injectable()
export class ImpersonationGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private configService: ConfigService,
    private usersService: UsersService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const targetUserId = request.headers['x-impersonate-user'];
    
    if (!targetUserId) return true;
    
    const adminUser = request.user;
    
    // Verify admin has permission to impersonate
    const allowedRoles = this.configService.get<string[]>('IMPERSONATION_ALLOWED_ROLES', ['admin']);
    const hasPermission = adminUser.roles.some(role => allowedRoles.includes(role));
    
    if (!hasPermission) {
      throw new Error('Insufficient permissions to impersonate');
    }
    
    // Look up the target user
    const targetUser = await this.usersService.findById(targetUserId);
    if (!targetUser) {
      throw new Error('Target user not found');
    }
    
    // Modify the request to use the target user's context
    request.user = { ...targetUser };
    request.impersonation = {
      originalUser: adminUser,
      targetUser: targetUser,
      initiatedAt: new Date().toISOString(),
    };
    
    return true;
  }
}