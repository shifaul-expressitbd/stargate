-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "public"."AccessEvent" ADD VALUE 'SUSPICIOUS_ACTIVITY_DETECTED';
ALTER TYPE "public"."AccessEvent" ADD VALUE 'IP_ADDRESS_CHANGED';
ALTER TYPE "public"."AccessEvent" ADD VALUE 'DEVICE_FINGERPRINT_CHANGED';
ALTER TYPE "public"."AccessEvent" ADD VALUE 'GEOLOCATION_CHANGED';
ALTER TYPE "public"."AccessEvent" ADD VALUE 'UNUSUAL_ACCESS_PATTERN';
ALTER TYPE "public"."AccessEvent" ADD VALUE 'SESSION_CONCURRENCY_LIMIT_EXCEEDED';
ALTER TYPE "public"."AccessEvent" ADD VALUE 'SESSION_RISK_SCORE_INCREASED';
ALTER TYPE "public"."AccessEvent" ADD VALUE 'SECURITY_ALERT_TRIGGERED';
ALTER TYPE "public"."AccessEvent" ADD VALUE 'DEVICE_FINGERPRINT_CAPTURED';
ALTER TYPE "public"."AccessEvent" ADD VALUE 'SESSION_ACTIVITY_MONITORED';
ALTER TYPE "public"."AccessEvent" ADD VALUE 'ACCOUNT_SECURITY_UPDATED';

-- AlterTable
ALTER TABLE "public"."user_sessions" ADD COLUMN     "accessCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "browserFingerprintHash" TEXT,
ADD COLUMN     "deviceFingerprintConfidence" DOUBLE PRECISION DEFAULT 0.5,
ADD COLUMN     "invalidatedAt" TIMESTAMP(3),
ADD COLUMN     "invalidationReason" TEXT,
ADD COLUMN     "lastIpChangeAt" TIMESTAMP(3),
ADD COLUMN     "latitude" DOUBLE PRECISION,
ADD COLUMN     "longitude" DOUBLE PRECISION,
ADD COLUMN     "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
ADD COLUMN     "timezone" TEXT,
ADD COLUMN     "unusualActivityCount" INTEGER NOT NULL DEFAULT 0;

-- CreateIndex
CREATE INDEX "user_sessions_riskScore_idx" ON "public"."user_sessions"("riskScore");

-- CreateIndex
CREATE INDEX "user_sessions_browserFingerprintHash_idx" ON "public"."user_sessions"("browserFingerprintHash");

-- Foreign key constraint renaming removed to avoid conflicts
