/*
  Warnings:

  - You are about to drop the `commands` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropTable
DROP TABLE "public"."commands";

-- CreateTable
CREATE TABLE "public"."sgtm_containers" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'created',
    "config" JSONB,

    CONSTRAINT "sgtm_containers_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "public"."sgtm_containers" ADD CONSTRAINT "sgtm_containers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
