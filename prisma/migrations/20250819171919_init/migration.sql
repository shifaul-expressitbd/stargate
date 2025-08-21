-- AlterTable
ALTER TABLE "public"."users" ADD COLUMN     "backupCodes" TEXT[] DEFAULT ARRAY[]::TEXT[];
