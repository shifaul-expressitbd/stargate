// src/admin/interfaces/impersonation-audit.interface.ts
export interface ImpersonationAuditLog {
  id?: string;
  adminId: string;
  adminEmail: string;
  targetId: string;
  targetEmail: string;
  action: 'start' | 'stop';
  reason?: string;
  ipAddress?: string;
  userAgent?: string;
  timestamp: Date;
}