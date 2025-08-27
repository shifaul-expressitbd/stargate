/*
  Warnings:

  - You are about to drop the column `action` on the `sgtm_containers` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "public"."sgtm_containers" DROP COLUMN "action",
ADD COLUMN     "containerId" TEXT,
ALTER COLUMN "fullName" DROP NOT NULL;
