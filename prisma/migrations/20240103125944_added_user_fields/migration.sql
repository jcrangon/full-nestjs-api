-- AlterTable
ALTER TABLE "users" ADD COLUMN     "active" TEXT NOT NULL DEFAULT '1',
ADD COLUMN     "forgotPasswordExp" TIMESTAMP(3),
ADD COLUMN     "forgotPasswordToken" TEXT,
ADD COLUMN     "role" TEXT NOT NULL DEFAULT 'ROLE_USER',
ADD COLUMN     "verifiedEmail" TEXT NOT NULL DEFAULT '0';
