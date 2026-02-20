-- CreateEnum
CREATE TYPE "UserType" AS ENUM ('USER', 'ADMIN');

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "userType" "UserType" NOT NULL DEFAULT 'USER';
