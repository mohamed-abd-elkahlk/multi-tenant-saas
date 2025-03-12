-- CreateEnum
CREATE TYPE "MFATYPE" AS ENUM ('Email', 'TOTP');

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "mfaType" "MFATYPE";
