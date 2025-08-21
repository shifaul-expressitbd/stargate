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
ALTER TABLE "public"."ImpersonationSession" ADD CONSTRAINT "ImpersonationSession_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationSession" ADD CONSTRAINT "ImpersonationSession_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationAudit" ADD CONSTRAINT "ImpersonationAudit_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."ImpersonationAudit" ADD CONSTRAINT "ImpersonationAudit_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
