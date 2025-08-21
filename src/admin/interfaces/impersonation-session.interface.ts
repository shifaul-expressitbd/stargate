// src/admin/interfaces/impersonation-session.interface.ts
export interface ActiveImpersonationSession {
  adminId: string;
  targetId: string;
  startedAt: Date;
  expiresAt: Date;
  reason?: string;
  ipAddress?: string;
  userAgent?: string;
}