import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { PrismaService } from '../database/prisma/prisma.service';
import { NotFoundException } from '@nestjs/common';

const mockPrismaService = {
  user: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    findMany: jest.fn(),
  },
};

describe('UsersService', () => {
  let service: UsersService;
  let prismaService: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        { provide: PrismaService, useValue: mockPrismaService },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    prismaService = module.get<PrismaService>(PrismaService);
    
    jest.clearAllMocks();
  });

  describe('findByEmail', () => {
    it('should return user by email', async () => {
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        name: 'Test User',
      };
      
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);
      
      const result = await service.findByEmail('test@example.com');
      
      expect(result).toEqual(mockUser);
      expect(mockPrismaService.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
      });
    });

    it('should return null if user not found', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);
      
      const result = await service.findByEmail('test@example.com');
      
      expect(result).toBeNull();
    });
  });

  describe('findById', () => {
    it('should return user by id', async () => {
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        name: 'Test User',
      };
      
      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);
      
      const result = await service.findById('1');
      
      expect(result).toEqual(mockUser);
      expect(mockPrismaService.user.findUnique).toHaveBeenCalledWith({
        where: { id: '1' },
      });
    });
  });

  describe('markEmailAsVerified', () => {
    it('should mark email as verified', async () => {
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        isEmailVerified: false,
      };
      
      const updatedUser = {
        ...mockUser,
        isEmailVerified: true,
        emailVerifiedAt: expect.any(Date),
        verificationToken: null,
      };
      
      mockPrismaService.user.update.mockResolvedValue(updatedUser);
      
      const result = await service.markEmailAsVerified('1');
      
      expect(result.isEmailVerified).toBe(true);
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: {
          isEmailVerified: true,
          emailVerifiedAt: expect.any(Date),
          verificationToken: null,
        },
      });
    });
  });

  // Add tests for other methods
});