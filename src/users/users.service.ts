import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../database/prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  async findById(id: string) {
    return this.prisma.user.findUnique({
      where: { id },
    });
  }

  async findByVerificationToken(token: string) {
    return this.prisma.user.findFirst({
      where: {
        verificationToken: token,
        // Ensure token is not null and not expired (optional)
        // You could add expiration logic here if needed
      },
    });
  }

  async markEmailAsVerified(userId: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        isEmailVerified: true,
        emailVerifiedAt: new Date(),
        verificationToken: null,
      },
    });
  }

  async create(data: {
    email: string;
    name: string;
    password?: string;
    avatar?: string | null;
    provider?: string; // Keep for backward compatibility but don't use in DB
    isEmailVerified?: boolean;
    emailVerifiedAt?: Date | null;
    verificationToken?: string | null;
  }) {
    return this.prisma.user.create({
      data: {
        email: data.email,
        name: data.name,
        password: data.password || null,
        avatar: data.avatar || null,
        isEmailVerified: data.isEmailVerified ?? false,
        emailVerifiedAt: data.emailVerifiedAt || null,
        verificationToken: data.verificationToken || null,
      },
    });
  }

  async update(id: string, data: Prisma.UserUpdateInput) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    return this.prisma.user.update({ where: { id }, data });
  }

  async delete(id: string) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    return this.prisma.user.delete({ where: { id } });
  }

  async findAll() {
    return this.prisma.user.findMany({
      select: {
        id: true,
        email: true,
        name: true,
        avatar: true,
        isEmailVerified: true,
        createdAt: true,
        updatedAt: true,
        // Don't include password in the response
      },
    });
  }

  // Add these methods to the UsersService class
  async findByResetToken(token: string) {
    return this.prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpires: {
          gt: new Date(), // Check if token is still valid
        },
      },
    });
  }

  async updateResetToken(
    userId: string,
    resetToken: string,
    resetTokenExpires: Date,
  ) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        resetToken,
        resetTokenExpires,
      },
    });
  }

  async resetPassword(userId: string, password: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        password,
        resetToken: null,
        resetTokenExpires: null,
      },
    });
  }

  async changePassword(userId: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    return this.prisma.user.update({
      where: { id: userId },
      data: { password },
    });
  }
}
