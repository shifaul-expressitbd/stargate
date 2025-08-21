import { SetMetadata } from '@nestjs/common';

export const IMPERSONATION_ALLOWED_KEY = 'impersonationAllowed';

export const ImpersonationAllowed = (value: boolean = true) =>
  SetMetadata(IMPERSONATION_ALLOWED_KEY, value);
