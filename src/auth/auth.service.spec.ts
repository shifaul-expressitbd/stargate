import {
  BadRequestException,
  ConflictException,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import * as bcrypt from 'bcryptjs';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { PrismaService } from '../database/prisma/prisma.service';
import { MailService } from '../mail/mail.service';
import { UsersService } from '../users/users.service';
import {
  AuthResponse,
  AuthService,
  TwoFactorRequiredResponse,
} from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginWithTwoFactorDto } from './dto/two-factor.dto';

// Interface for used emails storage
interface UsedEmails {
  emails: string[];
}

// Path to store used emails
const USED_EMAILS_FILE = join(__dirname, 'test-used-emails.json');

// Function to get a unique email
const getUniqueEmail = (): string => {
  let usedEmails: UsedEmails = { emails: [] };

  // Load existing used emails if file exists
  if (existsSync(USED_EMAILS_FILE)) {
    try {
      const data = readFileSync(USED_EMAILS_FILE, 'utf8');
      usedEmails = JSON.parse(data);
    } catch (error) {
      // If file is corrupt, start fresh
      usedEmails = { emails: [] };
    }
  }

  // Generate a unique email
  const baseEmail = 'testuser';
  let counter = 1;
  let email = `${baseEmail}${counter}@test.com`;

  while (usedEmails.emails.includes(email)) {
    counter++;
    email = `${baseEmail}${counter}@test.com`;
  }

  // Save the new email
  usedEmails.emails.push(email);
  writeFileSync(USED_EMAILS_FILE, JSON.stringify(usedEmails, null, 2), 'utf8');

  return email;
};

describe('AuthService', () => {
  let authService: AuthService;
  let usersService: UsersService;
  let jwtService: JwtService;
  let configService: ConfigService;
  let mailService: MailService;
  let prismaService: PrismaService;

  // Mock implementations
  const mockUsersService = {
    findByEmail: jest.fn(),
    findById: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    markEmailAsVerified: jest.fn(),
    updateResetToken: jest.fn(),
    resetPassword: jest.fn(),
    findByResetToken: jest.fn(), // Added missing method
  };

  const mockJwtService = {
    signAsync: jest.fn(),
    verifyAsync: jest.fn(),
  };

  const mockConfigService = {
    get: jest.fn(),
  };

  const mockMailService = {
    sendVerificationEmail: jest.fn(),
    sendPasswordResetEmail: jest.fn(),
  };

  const mockPrismaService = {
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
    authProvider: {
      findUnique: jest.fn(),
      create: jest.fn(),
      findFirst: jest.fn(),
      findMany: jest.fn(),
      updateMany: jest.fn(),
      delete: jest.fn(),
      count: jest.fn(),
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: mockUsersService },
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: MailService, useValue: mockMailService },
        { provide: PrismaService, useValue: mockPrismaService },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    usersService = module.get<UsersService>(UsersService);
    jwtService = module.get<JwtService>(JwtService);
    configService = module.get<ConfigService>(ConfigService);
    mailService = module.get<MailService>(MailService);
    prismaService = module.get<PrismaService>(PrismaService);

    // Mock config values
    mockConfigService.get.mockImplementation((key: string) => {
      switch (key) {
        case 'JWT_SECRET':
          return 'test-jwt-secret-which-is-long-enough';
        case 'JWT_REFRESH_SECRET':
          return 'test-jwt-refresh-secret-which-is-long-enough';
        case 'JWT_EXPIRES_IN':
          return '15m';
        case 'JWT_REFRESH_EXPIRES_IN':
          return '7d';
        case 'JWT_REFRESH_REMEMBER_ME_EXPIRES_IN':
          return '30d';
        default:
          return null;
      }
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('register', () => {
    it('should successfully register a new user', async () => {
      const registerDto: RegisterDto = {
        email: getUniqueEmail(),
        name: 'Test User',
        password: 'password123',
      };

      const hashedPassword = await bcrypt.hash(registerDto.password, 12);
      const mockUser = {
        id: 'user-id',
        email: registerDto.email,
        name: registerDto.name,
        avatar: null,
        password: hashedPassword,
        roles: ['USER'],
        isEmailVerified: false,
        isTwoFactorEnabled: false,
        verificationToken: 'token',
      };

      mockUsersService.findByEmail.mockResolvedValue(null);
      mockUsersService.create.mockResolvedValue(mockUser);
      mockPrismaService.authProvider.create.mockResolvedValue({});
      mockJwtService.signAsync.mockResolvedValue('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('refresh-token');

      const result = await authService.register(registerDto);

      expect(result.user.email).toBe(registerDto.email);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(mockMailService.sendVerificationEmail).toHaveBeenCalled();
    });

    it('should throw ConflictException if user already exists', async () => {
      const registerDto: RegisterDto = {
        email: getUniqueEmail(),
        name: 'Test User',
        password: 'password123',
      };

      mockUsersService.findByEmail.mockResolvedValue({ id: 'existing-user' });

      await expect(authService.register(registerDto)).rejects.toThrow(
        ConflictException,
      );
    });

    it('should throw BadRequestException if password is too short', async () => {
      const registerDto: RegisterDto = {
        email: getUniqueEmail(),
        name: 'Test User',
        password: 'short',
      };

      await expect(authService.register(registerDto)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('validateUser', () => {
    it('should validate user credentials successfully', async () => {
      const email = getUniqueEmail();
      const password = 'password123';
      const hashedPassword = await bcrypt.hash(password, 12);

      const mockUser = {
        id: 'user-id',
        email,
        password: hashedPassword,
        isEmailVerified: true,
        roles: ['USER'],
      };

      mockUsersService.findByEmail.mockResolvedValue(mockUser);
      mockPrismaService.authProvider.findUnique.mockResolvedValue(null);
      mockPrismaService.authProvider.create.mockResolvedValue({});

      const result = await authService.validateUser(email, password);

      expect(result.email).toBe(email);
      expect(result.password).toBeUndefined();
    });

    it('should throw UnauthorizedException for invalid credentials', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);

      await expect(
        authService.validateUser('wrong@email.com', 'wrongpassword'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException for unverified email', async () => {
      const mockUser = {
        id: 'user-id',
        email: getUniqueEmail(),
        password: await bcrypt.hash('password123', 12),
        isEmailVerified: false,
      };

      mockUsersService.findByEmail.mockResolvedValue(mockUser);

      await expect(
        authService.validateUser(mockUser.email, 'password123'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('login', () => {
    it('should login user without 2FA', async () => {
      const mockUser = {
        id: 'user-id',
        email: getUniqueEmail(),
        name: 'Test User',
        avatar: null,
        roles: ['USER'],
        isEmailVerified: true,
        isTwoFactorEnabled: false,
      };

      mockJwtService.signAsync.mockResolvedValue('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('refresh-token');
      mockPrismaService.authProvider.findFirst.mockResolvedValue({
        provider: 'LOCAL',
      });

      const result = (await authService.login(mockUser)) as AuthResponse;

      expect(result.user.email).toBe(mockUser.email);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });

    it('should return 2FA required response when 2FA is enabled', async () => {
      const mockUser = {
        id: 'user-id',
        email: getUniqueEmail(),
        name: 'Test User',
        roles: ['USER'],
        isEmailVerified: true,
        isTwoFactorEnabled: true,
      };

      mockJwtService.signAsync.mockResolvedValue('temp-token');

      const result = (await authService.login(
        mockUser,
      )) as TwoFactorRequiredResponse;

      expect(result.requiresTwoFactor).toBe(true);
      expect(result.tempToken).toBeDefined();
    });
  });

  describe('loginWithTwoFactor', () => {
    it('should login with valid 2FA code', async () => {
      const dto: LoginWithTwoFactorDto = {
        tempToken: 'valid-temp-token',
        code: '123456',
      };

      const mockUser = {
        id: 'user-id',
        email: getUniqueEmail(),
        name: 'Test User',
        roles: ['USER'],
        isEmailVerified: true,
        isTwoFactorEnabled: true,
        twoFactorSecret: 'secret',
      };

      const payload = { sub: mockUser.id, email: mockUser.email };

      mockJwtService.verifyAsync.mockResolvedValue(payload);
      mockUsersService.findById.mockResolvedValue(mockUser);
      jest.spyOn(authService, 'verifyTwoFactorCode').mockResolvedValue(true);
      mockJwtService.signAsync.mockResolvedValue('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('refresh-token');
      mockPrismaService.authProvider.findFirst.mockResolvedValue({
        provider: 'LOCAL',
      });

      const result = await authService.loginWithTwoFactor(dto);

      expect(result.user.email).toBe(mockUser.email);
      expect(result.accessToken).toBeDefined();
    });

    it('should throw error for invalid 2FA code', async () => {
      const dto: LoginWithTwoFactorDto = {
        tempToken: 'valid-temp-token',
        code: 'wrong-code',
      };

      const mockUser = {
        id: 'user-id',
        email: getUniqueEmail(),
        name: 'Test User',
        roles: ['USER'],
        isEmailVerified: true,
        isTwoFactorEnabled: true,
        twoFactorSecret: 'secret',
      };

      const payload = { sub: mockUser.id, email: mockUser.email };

      mockJwtService.verifyAsync.mockResolvedValue(payload);
      mockUsersService.findById.mockResolvedValue(mockUser);
      jest.spyOn(authService, 'verifyTwoFactorCode').mockResolvedValue(false);

      await expect(authService.loginWithTwoFactor(dto)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('refreshToken', () => {
    it('should refresh tokens successfully', async () => {
      const userId = 'user-id';
      const email = getUniqueEmail();

      const mockUser = {
        id: userId,
        email,
        name: 'Test User',
        roles: ['USER'],
        isEmailVerified: true,
        isTwoFactorEnabled: false,
      };

      mockUsersService.findById.mockResolvedValue(mockUser);
      mockJwtService.signAsync.mockResolvedValue('new-access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('new-access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('new-refresh-token');
      mockPrismaService.authProvider.findFirst.mockResolvedValue({
        provider: 'LOCAL',
      });

      const result = await authService.refreshToken(userId, email);

      expect(result.user.email).toBe(email);
      expect(result.accessToken).toBeDefined();
    });

    it('should throw error for non-existent user', async () => {
      mockUsersService.findById.mockResolvedValue(null);

      await expect(
        authService.refreshToken('non-existent-id', 'test@test.com'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('twoFactorAuthentication', () => {
    it('should generate 2FA secret successfully', async () => {
      const userId = 'user-id';
      const mockUser = {
        id: userId,
        email: getUniqueEmail(),
      };

      mockUsersService.findById.mockResolvedValue(mockUser);
      mockUsersService.update.mockResolvedValue({});

      const result = await authService.generateTwoFactorSecret(userId);

      expect(result).toHaveProperty('secret');
      expect(result).toHaveProperty('qrCodeUrl');
      expect(mockUsersService.update).toHaveBeenCalled();
    });

    it('should enable 2FA with valid code', async () => {
      const userId = 'user-id';
      const code = '123456';

      const mockUser = {
        id: userId,
        email: getUniqueEmail(),
        isTwoFactorEnabled: false,
        twoFactorSecret: 'test-secret',
      };

      mockUsersService.findById.mockResolvedValue(mockUser);
      jest.spyOn(authService, 'verifyTwoFactorCode').mockResolvedValue(true);
      mockUsersService.update.mockResolvedValue({});

      const result = await authService.enableTwoFactor(userId, code);

      expect(result).toBeDefined();
      expect(mockUsersService.update).toHaveBeenCalledWith(userId, {
        isTwoFactorEnabled: true,
        backupCodes: expect.anything(),
      });
    });

    it('should disable 2FA with valid code', async () => {
      const userId = 'user-id';
      const code = '123456';

      const mockUser = {
        id: userId,
        email: getUniqueEmail(),
        isTwoFactorEnabled: true,
        twoFactorSecret: 'test-secret',
      };

      mockUsersService.findById.mockResolvedValue(mockUser);
      jest.spyOn(authService, 'verifyTwoFactorCode').mockResolvedValue(true);
      mockUsersService.update.mockResolvedValue({});

      await authService.disableTwoFactor(userId, code);

      expect(mockUsersService.update).toHaveBeenCalledWith(userId, {
        isTwoFactorEnabled: false,
        twoFactorSecret: null,
        backupCodes: { set: [] },
      });
    });
  });

  describe('passwordReset', () => {
    it('should request password reset successfully', async () => {
      const email = getUniqueEmail();
      const mockUser = {
        id: 'user-id',
        email,
      };

      mockUsersService.findByEmail.mockResolvedValue(mockUser);
      mockUsersService.updateResetToken.mockResolvedValue({});

      await authService.requestPasswordReset(email);

      expect(mockMailService.sendPasswordResetEmail).toHaveBeenCalled();
    });

    it('should reset password with valid token', async () => {
      const token = 'valid-token';
      const newPassword = 'new-password123';

      const mockUser = {
        id: 'user-id',
        email: getUniqueEmail(),
      };

      mockUsersService.findByResetToken.mockResolvedValue(mockUser);
      mockUsersService.resetPassword.mockResolvedValue({});
      mockPrismaService.authProvider.findUnique.mockResolvedValue(null);
      mockPrismaService.authProvider.create.mockResolvedValue({});

      await authService.resetPassword(token, newPassword);

      expect(mockUsersService.resetPassword).toHaveBeenCalled();
    });

    it('should throw error for invalid reset token', async () => {
      mockUsersService.findByResetToken.mockResolvedValue(null);

      await expect(
        authService.resetPassword('invalid-token', 'new-password'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('changePassword', () => {
    it('should change password successfully', async () => {
      const userId = 'user-id';
      const currentPassword = 'old-password';
      const newPassword = 'new-password';

      const mockUser = {
        id: userId,
        email: getUniqueEmail(),
        password: await bcrypt.hash(currentPassword, 12),
      };

      mockUsersService.findById.mockResolvedValue(mockUser);
      mockUsersService.update.mockResolvedValue({});

      await authService.changePassword(userId, currentPassword, newPassword);

      expect(mockUsersService.update).toHaveBeenCalled();
    });

    it('should throw error for incorrect current password', async () => {
      const userId = 'user-id';
      const mockUser = {
        id: userId,
        email: getUniqueEmail(),
        password: await bcrypt.hash('real-password', 12),
      };

      mockUsersService.findById.mockResolvedValue(mockUser);

      await expect(
        authService.changePassword(userId, 'wrong-password', 'new-password'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('errorHandling', () => {
    it('should handle database errors gracefully', async () => {
      const registerDto: RegisterDto = {
        email: getUniqueEmail(),
        name: 'Test User',
        password: 'password123',
      };

      mockUsersService.findByEmail.mockRejectedValue(
        new Error('Database connection failed'),
      );

      await expect(authService.register(registerDto)).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should handle JWT secret validation errors', () => {
      // Temporarily override config to trigger secret validation error
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'JWT_SECRET') return 'short';
        return null;
      });

      expect(
        () =>
          new AuthService(
            usersService as any,
            jwtService as any,
            configService as any,
            mailService as any,
            prismaService as any,
          ),
      ).toThrow('JWT_SECRET is missing or too short');
    });
  });
});
