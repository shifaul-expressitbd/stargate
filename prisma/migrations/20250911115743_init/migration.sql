-- CreateEnum
CREATE TYPE "public"."ContainerStatus" AS ENUM ('CREATED', 'PENDING', 'RUNNING', 'STOPPED', 'ERROR', 'DELETED');

-- CreateEnum
CREATE TYPE "public"."AuthProviderType" AS ENUM ('LOCAL', 'GOOGLE', 'FACEBOOK', 'GITHUB', 'TWITTER', 'LINKEDIN', 'MICROSOFT', 'APPLE');

-- CreateEnum
CREATE TYPE "public"."AccessEvent" AS ENUM ('LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'TOKEN_REFRESH', 'PASSWORD_RESET_REQUEST', 'PASSWORD_RESET_SUCCESS', 'PASSWORD_CHANGE', 'SESSION_EXPIRED', 'SESSION_INVALIDATED', 'TWO_FACTOR_ENABLED', 'TWO_FACTOR_DISABLED', 'BACKUP_CODE_USED', 'PROVIDER_LINKED', 'PROVIDER_UNLINKED', 'IMPERSONATION_START', 'IMPERSONATION_END', 'SUSPICIOUS_ACTIVITY_DETECTED', 'IP_ADDRESS_CHANGED', 'DEVICE_FINGERPRINT_CHANGED', 'GEOLOCATION_CHANGED', 'UNUSUAL_ACCESS_PATTERN', 'SESSION_CONCURRENCY_LIMIT_EXCEEDED', 'SESSION_RISK_SCORE_INCREASED', 'SECURITY_ALERT_TRIGGERED', 'DEVICE_FINGERPRINT_CAPTURED', 'SESSION_ACTIVITY_MONITORED', 'ACCOUNT_SECURITY_UPDATED');

-- CreateTable
CREATE TABLE "public"."users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "password" TEXT,
    "avatar" TEXT,
    "isEmailVerified" BOOLEAN NOT NULL DEFAULT false,
    "emailVerifiedAt" TIMESTAMP(3),
    "verificationToken" TEXT,
    "twoFactorSecret" TEXT,
    "resetToken" TEXT,
    "resetTokenExpires" TIMESTAMP(3),
    "isTwoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
    "backupCodes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "roles" TEXT[] DEFAULT ARRAY['user']::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."auth_providers" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "provider" "public"."AuthProviderType" NOT NULL,
    "providerId" TEXT NOT NULL,
    "email" TEXT,
    "accessToken" TEXT,
    "refreshToken" TEXT,
    "tokenExpiresAt" TIMESTAMP(3),
    "providerData" JSONB,
    "isPrimary" BOOLEAN NOT NULL DEFAULT false,
    "linkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "auth_providers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."user_sessions" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "deviceInfo" JSONB,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "location" TEXT,
    "browserFingerprintHash" TEXT,
    "deviceFingerprintConfidence" DOUBLE PRECISION DEFAULT 0.5,
    "latitude" DOUBLE PRECISION,
    "longitude" DOUBLE PRECISION,
    "timezone" TEXT,
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "lastIpChangeAt" TIMESTAMP(3),
    "accessCount" INTEGER NOT NULL DEFAULT 0,
    "unusualActivityCount" INTEGER NOT NULL DEFAULT 0,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastActivity" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rememberMe" BOOLEAN NOT NULL DEFAULT false,
    "invalidatedAt" TIMESTAMP(3),
    "invalidationReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."refresh_tokens" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "tokenFamily" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "usedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "refresh_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."sgtm_containers" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "fullName" TEXT,
    "containerId" TEXT,
    "userId" TEXT NOT NULL,
    "status" "public"."ContainerStatus" NOT NULL DEFAULT 'CREATED',
    "subdomain" TEXT,
    "config" TEXT,
    "regionKey" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sgtm_containers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."meta_capi_containers" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "fullName" TEXT,
    "fbPixelId" TEXT NOT NULL,
    "accessToken" TEXT NOT NULL,
    "testCode" TEXT,
    "userId" TEXT NOT NULL,
    "status" "public"."ContainerStatus" NOT NULL DEFAULT 'CREATED',
    "regionKey" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "meta_capi_containers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."sgtm_regions" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "apiUrl" TEXT NOT NULL,
    "apiKey" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sgtm_regions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."meta_capi_regions" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "baseUrl" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "appSecret" TEXT NOT NULL,
    "apiVersion" TEXT NOT NULL DEFAULT 'v16.0',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "meta_capi_regions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."ImpersonationSession" (
    "id" TEXT NOT NULL,
    "adminId" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "reason" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ImpersonationSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."ImpersonationAudit" (
    "id" TEXT NOT NULL,
    "adminId" TEXT NOT NULL,
    "adminEmail" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "targetEmail" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "reason" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ImpersonationAudit_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."access_logs" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "event" "public"."AccessEvent" NOT NULL,
    "sessionId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "location" TEXT,
    "deviceInfo" JSONB,
    "success" BOOLEAN NOT NULL DEFAULT true,
    "failureReason" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "access_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "public"."users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "users_verificationToken_key" ON "public"."users"("verificationToken");

-- CreateIndex
CREATE UNIQUE INDEX "users_resetToken_key" ON "public"."users"("resetToken");

-- CreateIndex
CREATE INDEX "auth_providers_userId_idx" ON "public"."auth_providers"("userId");

-- CreateIndex
CREATE INDEX "auth_providers_provider_idx" ON "public"."auth_providers"("provider");

-- CreateIndex
CREATE INDEX "auth_providers_providerId_idx" ON "public"."auth_providers"("providerId");

-- CreateIndex
CREATE UNIQUE INDEX "auth_providers_userId_provider_key" ON "public"."auth_providers"("userId", "provider");

-- CreateIndex
CREATE UNIQUE INDEX "user_sessions_sessionId_key" ON "public"."user_sessions"("sessionId");

-- CreateIndex
CREATE INDEX "user_sessions_userId_idx" ON "public"."user_sessions"("userId");

-- CreateIndex
CREATE INDEX "user_sessions_sessionId_idx" ON "public"."user_sessions"("sessionId");

-- CreateIndex
CREATE INDEX "user_sessions_expiresAt_idx" ON "public"."user_sessions"("expiresAt");

-- CreateIndex
CREATE INDEX "user_sessions_isActive_idx" ON "public"."user_sessions"("isActive");

-- CreateIndex
CREATE INDEX "user_sessions_riskScore_idx" ON "public"."user_sessions"("riskScore");

-- CreateIndex
CREATE INDEX "user_sessions_browserFingerprintHash_idx" ON "public"."user_sessions"("browserFingerprintHash");

-- CreateIndex
CREATE UNIQUE INDEX "refresh_tokens_tokenHash_key" ON "public"."refresh_tokens"("tokenHash");

-- CreateIndex
CREATE INDEX "refresh_tokens_sessionId_idx" ON "public"."refresh_tokens"("sessionId");

-- CreateIndex
CREATE INDEX "refresh_tokens_tokenHash_idx" ON "public"."refresh_tokens"("tokenHash");

-- CreateIndex
CREATE INDEX "refresh_tokens_expiresAt_idx" ON "public"."refresh_tokens"("expiresAt");

-- CreateIndex
CREATE INDEX "refresh_tokens_isActive_idx" ON "public"."refresh_tokens"("isActive");

-- CreateIndex
CREATE INDEX "sgtm_containers_regionKey_idx" ON "public"."sgtm_containers"("regionKey");

-- CreateIndex
CREATE INDEX "meta_capi_containers_regionKey_idx" ON "public"."meta_capi_containers"("regionKey");

-- CreateIndex
CREATE UNIQUE INDEX "sgtm_regions_key_key" ON "public"."sgtm_regions"("key");

-- CreateIndex
CREATE INDEX "sgtm_regions_key_idx" ON "public"."sgtm_regions"("key");

-- CreateIndex
CREATE INDEX "sgtm_regions_isActive_idx" ON "public"."sgtm_regions"("isActive");

-- CreateIndex
CREATE INDEX "sgtm_regions_isDefault_idx" ON "public"."sgtm_regions"("isDefault");

-- CreateIndex
CREATE UNIQUE INDEX "meta_capi_regions_key_key" ON "public"."meta_capi_regions"("key");

-- CreateIndex
CREATE INDEX "meta_capi_regions_key_idx" ON "public"."meta_capi_regions"("key");

-- CreateIndex
CREATE INDEX "meta_capi_regions_isActive_idx" ON "public"."meta_capi_regions"("isActive");

-- CreateIndex
CREATE INDEX "meta_capi_regions_isDefault_idx" ON "public"."meta_capi_regions"("isDefault");

-- CreateIndex
CREATE UNIQUE INDEX "ImpersonationSession_targetId_key" ON "public"."ImpersonationSession"("targetId");

-- CreateIndex
CREATE INDEX "ImpersonationSession_adminId_idx" ON "public"."ImpersonationSession"("adminId");

-- CreateIndex
CREATE INDEX "ImpersonationSession_targetId_idx" ON "public"."ImpersonationSession"("targetId");

-- CreateIndex
CREATE INDEX "ImpersonationSession_expiresAt_idx" ON "public"."ImpersonationSession"("expiresAt");

-- CreateIndex
CREATE INDEX "ImpersonationAudit_adminId_timestamp_idx" ON "public"."ImpersonationAudit"("adminId", "timestamp");

-- CreateIndex
CREATE INDEX "ImpersonationAudit_targetId_timestamp_idx" ON "public"."ImpersonationAudit"("targetId", "timestamp");

-- CreateIndex
CREATE INDEX "ImpersonationAudit_action_timestamp_idx" ON "public"."ImpersonationAudit"("action", "timestamp");

-- CreateIndex
CREATE INDEX "access_logs_userId_idx" ON "public"."access_logs"("userId");

-- CreateIndex
CREATE INDEX "access_logs_sessionId_idx" ON "public"."access_logs"("sessionId");

-- CreateIndex
CREATE INDEX "access_logs_event_idx" ON "public"."access_logs"("event");

-- CreateIndex
CREATE INDEX "access_logs_timestamp_idx" ON "public"."access_logs"("timestamp");

-- CreateIndex
CREATE INDEX "access_logs_userId_event_idx" ON "public"."access_logs"("userId", "event");

-- AddForeignKey
ALTER TABLE "public"."auth_providers" ADD CONSTRAINT "auth_providers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."user_sessions" ADD CONSTRAINT "user_sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."refresh_tokens" ADD CONSTRAINT "refresh_tokens_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "public"."user_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."sgtm_containers" ADD CONSTRAINT "sgtm_containers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."sgtm_containers" ADD CONSTRAINT "sgtm_containers_regionKey_fkey" FOREIGN KEY ("regionKey") REFERENCES "public"."sgtm_regions"("key") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."meta_capi_containers" ADD CONSTRAINT "meta_capi_containers_user_id_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."meta_capi_containers" ADD CONSTRAINT "meta_capi_containers_regionKey_fkey" FOREIGN KEY ("regionKey") REFERENCES "public"."meta_capi_regions"("key") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."meta_capi_containers" ADD CONSTRAINT "meta_capi_containers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationSession" ADD CONSTRAINT "ImpersonationSession_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationSession" ADD CONSTRAINT "ImpersonationSession_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationAudit" ADD CONSTRAINT "ImpersonationAudit_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationAudit" ADD CONSTRAINT "ImpersonationAudit_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."access_logs" ADD CONSTRAINT "access_logs_user_id_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."access_logs" ADD CONSTRAINT "access_logs_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
