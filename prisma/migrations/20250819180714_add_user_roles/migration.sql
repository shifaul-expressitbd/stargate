-- AlterTable
ALTER TABLE "public"."users" ADD COLUMN     "roles" TEXT[] DEFAULT ARRAY['user']::TEXT[];
