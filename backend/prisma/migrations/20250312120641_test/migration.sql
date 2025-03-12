/*
  Warnings:

  - You are about to drop the column `mfaType` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "mfaType",
ADD COLUMN     "mfaMethods" JSONB,
ADD COLUMN     "mfaSecrets" JSONB;

-- DropEnum
DROP TYPE "MFATYPE";
