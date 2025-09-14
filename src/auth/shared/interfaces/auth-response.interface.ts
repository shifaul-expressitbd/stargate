export interface AuthResponse {
  user: {
    id: string;
    email: string;
    name: string;
    avatar?: string | null;
    provider: string;
    isEmailVerified: boolean;
    isTwoFactorEnabled: boolean;
  };
  accessToken: string;
  refreshToken: string;
}

export interface TwoFactorRequiredResponse {
  requiresTwoFactor: true;
  userId: string;
  email: string;
  tempToken: string;
}

export interface RegisterResponse {
  user: {
    id: string;
    email: string;
    name: string;
    avatar?: string | null;
    provider: string;
    isEmailVerified: boolean;
    isTwoFactorEnabled: boolean;
  };
}

export interface TwoFactorGenerateResponse {
  secret: string;
  qrCodeUrl: string;
  manualEntryKey: string;
  otpAuthUrl: string;
}

export interface TwoFactorEnableResponse {
  backupCodes?: string[];
}

export interface TwoFactorStatusResponse {
  isEnabled: boolean;
  hasSecret: boolean;
}
