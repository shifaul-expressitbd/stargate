/*
  Warnings:

  - You are about to drop the column `autoRemove` on the `sgtm_containers` table. All the data in the column will be lost.
  - You are about to drop the column `env` on the `sgtm_containers` table. All the data in the column will be lost.
  - You are about to drop the column `image` on the `sgtm_containers` table. All the data in the column will be lost.
  - You are about to drop the column `network` on the `sgtm_containers` table. All the data in the column will be lost.
  - You are about to drop the column `port` on the `sgtm_containers` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "public"."sgtm_containers_fullName_key";

-- AlterTable
ALTER TABLE "public"."sgtm_containers" DROP COLUMN "autoRemove",
DROP COLUMN "env",
DROP COLUMN "image",
DROP COLUMN "network",
DROP COLUMN "port",
ALTER COLUMN "config" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "public"."users" ADD COLUMN     "isTwoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "twoFactorSecret" TEXT;
