-- CreateEnum
CREATE TYPE "public"."ContainerStatus" AS ENUM ('CREATED', 'PENDING', 'RUNNING', 'STOPPED', 'ERROR', 'DELETED');

-- CreateEnum
CREATE TYPE "public"."AuthProviderType" AS ENUM ('LOCAL', 'GOOGLE', 'FACEBOOK', 'GITHUB', 'TWITTER', 'LINKEDIN', 'MICROSOFT', 'APPLE');

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
    "refreshTokenHash" TEXT,
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
CREATE TABLE "public"."sgtm_containers" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "status" "public"."ContainerStatus" NOT NULL DEFAULT 'CREATED',
    "action" TEXT,
    "subdomain" TEXT,
    "config" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sgtm_containers_pkey" PRIMARY KEY ("id")
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

-- AddForeignKey
ALTER TABLE "public"."auth_providers" ADD CONSTRAINT "auth_providers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."sgtm_containers" ADD CONSTRAINT "sgtm_containers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationSession" ADD CONSTRAINT "ImpersonationSession_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationSession" ADD CONSTRAINT "ImpersonationSession_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationAudit" ADD CONSTRAINT "ImpersonationAudit_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationAudit" ADD CONSTRAINT "ImpersonationAudit_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
