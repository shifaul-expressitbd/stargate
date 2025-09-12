/*
  Warnings:

  - You are about to drop the column `relatedReplyId` on the `file_metadata` table. All the data in the column will be lost.
  - You are about to drop the column `relatedTicketId` on the `file_metadata` table. All the data in the column will be lost.
  - You are about to drop the column `uploadedById` on the `file_metadata` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[storageKey]` on the table `file_metadata` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `storageKey` to the `file_metadata` table without a default value. This is not possible if the table is not empty.
  - Added the required column `storageProvider` to the `file_metadata` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "public"."file_metadata" DROP CONSTRAINT "file_metadata_relatedReplyId_fkey";

-- DropForeignKey
ALTER TABLE "public"."file_metadata" DROP CONSTRAINT "file_metadata_relatedTicketId_fkey";

-- DropForeignKey
ALTER TABLE "public"."file_metadata" DROP CONSTRAINT "file_metadata_uploadedById_fkey";

-- DropIndex
DROP INDEX "public"."file_metadata_relatedReplyId_idx";

-- DropIndex
DROP INDEX "public"."file_metadata_relatedTicketId_idx";

-- DropIndex
DROP INDEX "public"."file_metadata_uploadedById_idx";

-- AlterTable
ALTER TABLE "public"."file_metadata" DROP COLUMN "relatedReplyId",
DROP COLUMN "relatedTicketId",
DROP COLUMN "uploadedById",
ADD COLUMN     "category" TEXT,
ADD COLUMN     "checksum" TEXT,
ADD COLUMN     "expiresAt" TIMESTAMP(3),
ADD COLUMN     "processingStatus" TEXT,
ADD COLUMN     "securityStatus" TEXT,
ADD COLUMN     "storageBucket" TEXT,
ADD COLUMN     "storageKey" TEXT NOT NULL,
ADD COLUMN     "storageProvider" TEXT NOT NULL,
ADD COLUMN     "storageRegion" TEXT,
ADD COLUMN     "storageUrl" TEXT,
ADD COLUMN     "supportTicketId" TEXT,
ADD COLUMN     "ticketReplyId" TEXT,
ADD COLUMN     "userId" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "file_metadata_storageKey_key" ON "public"."file_metadata"("storageKey");

-- CreateIndex
CREATE INDEX "file_metadata_category_idx" ON "public"."file_metadata"("category");

-- CreateIndex
CREATE INDEX "file_metadata_securityStatus_idx" ON "public"."file_metadata"("securityStatus");

-- CreateIndex
CREATE INDEX "file_metadata_processingStatus_idx" ON "public"."file_metadata"("processingStatus");

-- CreateIndex
CREATE INDEX "file_metadata_createdAt_idx" ON "public"."file_metadata"("createdAt");

-- CreateIndex
CREATE INDEX "file_metadata_storageProvider_idx" ON "public"."file_metadata"("storageProvider");

-- CreateIndex
CREATE INDEX "file_metadata_storageKey_idx" ON "public"."file_metadata"("storageKey");

-- CreateIndex
CREATE INDEX "file_metadata_storageProvider_createdAt_idx" ON "public"."file_metadata"("storageProvider", "createdAt");

-- RenameForeignKey
ALTER TABLE "public"."meta_capi_containers" RENAME CONSTRAINT "meta_capi_containers_user_id_fkey" TO "meta_capi_containers_user_id_fkey2";

-- AddForeignKey
ALTER TABLE "public"."file_metadata" ADD CONSTRAINT "file_metadata_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."file_metadata" ADD CONSTRAINT "file_metadata_supportTicketId_fkey" FOREIGN KEY ("supportTicketId") REFERENCES "public"."support_tickets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."file_metadata" ADD CONSTRAINT "file_metadata_ticketReplyId_fkey" FOREIGN KEY ("ticketReplyId") REFERENCES "public"."ticket_replies"("id") ON DELETE SET NULL ON UPDATE CASCADE;
