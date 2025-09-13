/*
  Warnings:

  - You are about to drop the column `checksum` on the `file_metadata` table. All the data in the column will be lost.
  - You are about to drop the column `expiresAt` on the `file_metadata` table. All the data in the column will be lost.
  - You are about to drop the column `storageBucket` on the `file_metadata` table. All the data in the column will be lost.
  - You are about to drop the column `storageRegion` on the `file_metadata` table. All the data in the column will be lost.
  - You are about to drop the column `userId` on the `file_metadata` table. All the data in the column will be lost.
  - You are about to drop the column `supportTicketId` on the `file_metadata` table. All the data in the column will be lost.
  - You are about to drop the column `ticketReplyId` on the `file_metadata` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "public"."file_metadata" DROP COLUMN "checksum",
DROP COLUMN "expiresAt",
DROP COLUMN "storageBucket",
DROP COLUMN "storageRegion",
DROP COLUMN "userId",
DROP COLUMN "supportTicketId",
DROP COLUMN "ticketReplyId";