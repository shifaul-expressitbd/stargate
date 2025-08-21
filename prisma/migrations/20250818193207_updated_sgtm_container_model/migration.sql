/*
  Warnings:

  - The `status` column on the `sgtm_containers` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - A unique constraint covering the columns `[fullName]` on the table `sgtm_containers` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `fullName` to the `sgtm_containers` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "public"."ContainerStatus" AS ENUM ('CREATED', 'PENDING', 'RUNNING', 'STOPPED', 'ERROR', 'DELETED');

-- AlterTable
ALTER TABLE "public"."sgtm_containers" ADD COLUMN     "action" TEXT,
ADD COLUMN     "autoRemove" BOOLEAN DEFAULT false,
ADD COLUMN     "env" JSONB,
ADD COLUMN     "fullName" TEXT NOT NULL,
ADD COLUMN     "image" TEXT DEFAULT 'ghcr.io/calquick/gtm-unified:latest',
ADD COLUMN     "network" TEXT DEFAULT 'bridge',
ADD COLUMN     "port" INTEGER DEFAULT 8080,
ADD COLUMN     "subdomain" TEXT,
DROP COLUMN "status",
ADD COLUMN     "status" "public"."ContainerStatus" NOT NULL DEFAULT 'CREATED';

-- CreateIndex
CREATE UNIQUE INDEX "sgtm_containers_fullName_key" ON "public"."sgtm_containers"("fullName");
