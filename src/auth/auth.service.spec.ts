import {
  BadRequestException,
  ConflictException,
  InternalServerErrorException,
  NotFoundException,
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

// Mocks for external dependencies
jest.mock('googleapis', () => ({
  google: {
    auth: {
      OAuth2: jest
        .fn()
        .mockImplementation((clientId, clientSecret, callbackUrl) => ({
          clientId,
          clientSecret,
          callbackUrl,
          credentials: {},
        })),
    },
  },
}));

jest.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: jest.fn().mockReturnValue('JBSWY3DPEHPK3PXP'),
    keyuri: jest
      .fn()
      .mockReturnValue(
        'otpauth://totp/StarGate:test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=StarGate',
      ),
  },
  totp: {
    options: {},
    generate: jest.fn().mockReturnValue('123456'),
    check: jest.fn().mockReturnValue(true),
  },
}));

jest.mock('qrcode-generator', () => ({
  __esModule: true,
  default: (version, ecLevel) => ({
    addData: function (data) {},
    make: function () {},
    createDataURL: function (size) {
      return 'data:image/png;base64,mockedQrContent';
    },
    createImgTag: function (size) {
      return '<img src="data:image/png;base64,mockedQrContent">';
    },
  }),
}));

jest.mock('bcryptjs', () => ({
  hash: jest
    .fn()
    .mockImplementation((password, saltRounds) =>
      Promise.resolve(`hashed_${password}`),
    ),
  compare: jest.fn().mockResolvedValue(true), // Default to true, will be overridden in specific tests
}));

// Updated to include dynamic compare behavior for specific tests

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

  const mockGoogleApis = {
    auth: {
      OAuth2: jest
        .fn()
        .mockImplementation((clientId, clientSecret, callbackUrl) => ({
          clientId,
          clientSecret,
          callbackUrl,
        })),
    },
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
      update: jest.fn(),
      updateMany: jest.fn(),
      delete: jest.fn(),
      count: jest.fn(),
    },
  };

  const setupConfigMock = () => {
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
        case 'GOOGLE_CLIENT_ID':
          return 'client-id';
        case 'GOOGLE_CLIENT_SECRET':
          return 'client-secret';
        case 'GOOGLE_CALLBACK_URL':
          return 'https://example.com/callback';
        default:
          return null;
      }
    });
  };

  beforeEach(async () => {
    console.log(
      `🔧 [Test Setup] Initializing test environment for: ${expect.getState().currentTestName}`,
    );

    setupConfigMock();

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

    console.log('🔧 [Test Setup] AuthService initialized successfully');
  });

  afterEach(() => {
    console.log(
      `🧹 [Test Cleanup] Cleaning up after test: ${expect.getState().currentTestName}`,
    );

    // Enhanced cleanup to prevent mock corruption between tests
    jest.clearAllMocks();
    jest.restoreAllMocks();

    // Restore original config mock implementation to prevent persistence
    setupConfigMock();

    // Clear any test environment variables we might have set
    delete process.env.TEST_NAME;

    console.log('🧹 [Test Cleanup] Mock state restored successfully');
  });

  describe('register', () => {
    it('should successfully register a new user', async () => {
      const registerDto: RegisterDto = {
        email: getUniqueEmail(),
        name: 'Test User',
        password: 'password123',
      };

      console.log('=== Test: register new user ===');
      console.log('Input Payload:', JSON.stringify(registerDto, null, 2));

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
      mockPrismaService.user.findUnique.mockResolvedValue({
        id: mockUser.id,
        email: mockUser.email,
        name: mockUser.name,
        avatar: null,
        password: mockUser.password,
        roles: mockUser.roles,
        isEmailVerified: false,
        isTwoFactorEnabled: false,
        verificationToken: mockUser.verificationToken,
        authProviders: [
          { provider: 'LOCAL', isPrimary: true, linkedAt: new Date() },
        ],
      });

      const result = await authService.register(registerDto);

      console.log('Service Response:', JSON.stringify(result, null, 2));
      console.log('Expected Response Structure:', {
        user: {
          id: 'string',
          email: registerDto.email,
          name: registerDto.name,
          avatar: 'nullable',
          isTwoFactorEnabled: false,
        },
        accessToken: 'string',
        refreshToken: 'string',
      });

      expect(result.user.email).toBe(registerDto.email);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(mockMailService.sendVerificationEmail).toHaveBeenCalled();

      console.log('Test Passed: ✅ User registration successful');
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

      mockUsersService.findByEmail.mockResolvedValue(null);

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

      console.log('=== Test: validate user credentials ===');
      console.log('Input Payload:', {
        email,
        password: 'hashed_' + hashedPassword.substring(7, 15) + '...',
      });

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

      console.log('Service Response:', JSON.stringify(result, null, 2));
      console.log('Expected Response:', {
        id: 'string',
        email: email,
        name: 'string',
        avatar: 'nullable',
        provider: 'string',
        password: 'undefined',
        verificationToken: 'undefined',
      });

      expect(result.email).toBe(email);
      expect(result.password).toBeUndefined();

      console.log('Test Passed: ✅ User credentials validated successfully');
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

      console.log('=== Test: generate 2FA secret ===');
      console.log('Input Payload:', { userId, userEmail: mockUser.email });

      mockUsersService.findById.mockResolvedValue(mockUser);
      mockUsersService.update.mockResolvedValue({});

      const result = await authService.generateTwoFactorSecret(userId);

      console.log('Service Response:', JSON.stringify(result, null, 2));
      console.log('Expected Response:', {
        secret: result.secret?.substring(0, 10) + '...',
        qrCodeUrl: 'data:image/png;base64,mockedQrContent',
        manualEntryKey: result.secret,
        otpAuthUrl: result.otpAuthUrl?.substring(0, 50) + '...',
      });

      expect(result).toHaveProperty('secret');
      expect(result).toHaveProperty('qrCodeUrl');
      expect(result.qrCodeUrl).toBe('data:image/png;base64,mockedQrContent');
      expect(mockUsersService.update).toHaveBeenCalled();

      console.log('Test Passed: ✅ 2FA secret generated successfully');
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

  describe('OAuth', () => {
    describe('validateOAuthUser', () => {
      it('should validate and create new OAuth user', async () => {
        const oauthUser = {
          email: 'oauth@example.com',
          name: 'OAuth User',
          avatar: 'https://avatar.example.com/photo.jpg',
          provider: 'google',
          providerId: 'google-123',
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
          tokenExpiresAt: new Date(Date.now() + 3600000),
          providerData: { profile: { id: 'google-123' } },
        };

        const mockCreatedUser = {
          id: 'user-id',
          email: oauthUser.email,
          name: oauthUser.name,
          avatar: oauthUser.avatar,
          provider: oauthUser.provider,
          isEmailVerified: true,
          roles: ['USER'],
        };

        mockUsersService.findByEmail.mockResolvedValue(null);
        mockUsersService.create.mockResolvedValue(mockCreatedUser);
        mockPrismaService.authProvider.findUnique.mockResolvedValue(null);
        mockPrismaService.authProvider.create.mockResolvedValue({});
        mockPrismaService.authProvider.count.mockResolvedValue(0);

        const result = await authService.validateOAuthUser(oauthUser);

        expect(mockUsersService.create).toHaveBeenCalledWith({
          email: oauthUser.email.toLowerCase().trim(),
          name: oauthUser.name.trim(),
          avatar: oauthUser.avatar,
          provider: oauthUser.provider,
          isEmailVerified: true,
          emailVerifiedAt: expect.any(Date),
          verificationToken: null,
        });
        expect(result).toEqual(mockCreatedUser);
      });

      it('should validate existing OAuth user and refresh tokens', async () => {
        const oauthUser = {
          email: 'existing@example.com',
          name: 'Existing User',
          provider: 'google',
          providerId: 'google-456',
          accessToken: 'new-access-token',
          refreshToken: 'new-refresh-token',
        };

        const mockExistingUser = {
          id: 'existing-user-id',
          email: oauthUser.email,
          name: oauthUser.name,
          isEmailVerified: false,
        };

        const mockExistingProvider = {
          id: 'provider-id',
          providerData: { old: 'data' },
        };

        mockUsersService.findByEmail.mockResolvedValue(mockExistingUser);
        mockPrismaService.authProvider.findUnique.mockResolvedValue(
          mockExistingProvider,
        );
        mockUsersService.markEmailAsVerified.mockResolvedValue({});
        mockPrismaService.authProvider.update.mockResolvedValue({});

        const result = await authService.validateOAuthUser(oauthUser);

        expect(mockUsersService.markEmailAsVerified).toHaveBeenCalledWith(
          mockExistingUser.id,
        );
        expect(mockPrismaService.authProvider.update).toHaveBeenCalledWith({
          where: { id: mockExistingProvider.id },
          data: expect.objectContaining({
            accessToken: oauthUser.accessToken,
            refreshToken: oauthUser.refreshToken,
            lastUsedAt: expect.any(Date),
          }),
        });
        expect(result).toEqual(mockExistingUser);
      });

      it('should create new auth provider for existing user', async () => {
        const oauthUser = {
          email: 'user@example.com',
          name: 'User',
          provider: 'github',
          providerId: 'github-789',
          accessToken: 'access-token',
        };

        const mockExistingUser = {
          id: 'user-id',
          email: oauthUser.email,
        };

        mockUsersService.findByEmail.mockResolvedValue(mockExistingUser);
        mockPrismaService.authProvider.findUnique.mockResolvedValue(null);
        mockPrismaService.authProvider.create.mockResolvedValue({});
        mockPrismaService.authProvider.count.mockResolvedValue(0);

        await authService.validateOAuthUser(oauthUser);

        expect(mockPrismaService.authProvider.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            userId: mockExistingUser.id,
            provider: 'GITHUB',
            providerId: oauthUser.providerId,
            email: oauthUser.email,
            accessToken: oauthUser.accessToken,
            isPrimary: false,
          }),
        });
      });
    });

    describe('getGoogleOAuth2Client', () => {
      it('should create and return OAuth2 client with correct configuration', async () => {
        mockConfigService.get.mockImplementation((key: string) => {
          switch (key) {
            case 'GOOGLE_CLIENT_ID':
              return 'client-id';
            case 'GOOGLE_CLIENT_SECRET':
              return 'client-secret';
            case 'GOOGLE_CALLBACK_URL':
              return 'https://example.com/callback';
          }
        });

        const client = await authService.getGoogleOAuth2Client();

        expect(client).toBeDefined();
        expect(typeof client).toBe('object');
      });

      it('should throw UnauthorizedException when config is missing', async () => {
        mockConfigService.get.mockReturnValue(null);

        await expect(authService.getGoogleOAuth2Client()).rejects.toThrow(
          UnauthorizedException,
        );
      });
    });

    describe('getGoogleTokens', () => {
      it('should return Google tokens for user with Google auth provider', async () => {
        const userId = 'user-id';
        const mockProvider = {
          accessToken: 'access-token',
          userId,
        };

        mockPrismaService.authProvider.findUnique.mockResolvedValue(
          mockProvider,
        );

        const result = await authService.getGoogleTokens(userId);

        expect(result).toEqual({ accessToken: 'access-token' });
        expect(mockPrismaService.authProvider.findUnique).toHaveBeenCalledWith({
          where: {
            userId_provider: {
              userId,
              provider: 'GOOGLE',
            },
          },
        });
      });

      it('should throw UnauthorizedException when Google provider not found', async () => {
        mockPrismaService.authProvider.findUnique.mockResolvedValue(null);

        await expect(authService.getGoogleTokens('user-id')).rejects.toThrow(
          UnauthorizedException,
        );
      });
    });

    describe('googleLogin', () => {
      it('should complete Google OAuth login successfully', async () => {
        const mockGoogleUser = {
          email: 'google@example.com',
          name: 'Google User',
          picture: 'https://avatar.google.com/photo.jpg',
          googleId: 'google-123',
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
        };

        const mockValidatedUser = {
          id: 'user-id',
          email: mockGoogleUser.email,
          name: mockGoogleUser.name,
          isTwoFactorEnabled: false,
        };

        mockUsersService.findByEmail.mockResolvedValue(mockValidatedUser);
        mockJwtService.signAsync.mockResolvedValue('access-token');
        mockJwtService.signAsync.mockResolvedValueOnce('access-token');
        mockJwtService.signAsync.mockResolvedValueOnce('refresh-token');
        mockPrismaService.authProvider.findFirst.mockResolvedValue({
          provider: 'GOOGLE',
        });

        const result = await authService.googleLogin(mockGoogleUser);

        expect(result.user.email).toBe(mockGoogleUser.email);
        expect(result.accessToken).toBeDefined();
        expect(result.refreshToken).toBeDefined();
      });

      it('should throw BadRequestException when 2FA is required', async () => {
        const mockGoogleUser = {
          email: 'google@example.com',
          name: 'Google User',
          picture: 'https://avatar.google.com/photo.jpg',
          googleId: 'google-123',
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
        };

        const mockValidatedUser = {
          id: 'user-id',
          email: mockGoogleUser.email,
          isTwoFactorEnabled: true,
        };

        mockUsersService.findByEmail.mockResolvedValue(mockValidatedUser);

        await expect(authService.googleLogin(mockGoogleUser)).rejects.toThrow(
          BadRequestException,
        );
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
        password: 'hashed_real-password', // Use mocked bcrypt hash format
      };

      mockUsersService.findById.mockResolvedValue(mockUser);

      // Temporarily mock bcrypt.compare to return false
      const bcryptMock = require('bcryptjs');
      const originalCompare = bcryptMock.compare;
      bcryptMock.compare = jest.fn().mockResolvedValueOnce(false);

      try {
        await expect(
          authService.changePassword(userId, 'wrong-password', 'new-password'),
        ).rejects.toThrow(UnauthorizedException);
      } finally {
        // Restore the original mock
        bcryptMock.compare = originalCompare;
      }
    });
  });

  describe('generateTokens', () => {
    it('should generate access and refresh tokens', async () => {
      const userId = 'user-id';
      const email = 'test@example.com';
      const roles = ['USER'];

      mockJwtService.signAsync.mockResolvedValueOnce('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('refresh-token');

      const result = await authService.generateTokens(userId, email, roles);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(mockJwtService.signAsync).toHaveBeenCalledTimes(2);
    });

    it('should generate tokens with remember me flag', async () => {
      const userId = 'user-id';
      const email = 'test@example.com';
      const roles = ['USER'];

      mockConfigService.get.mockImplementation((key: string) => {
        switch (key) {
          case 'JWT_EXPIRES_IN':
            return '15m';
          case 'JWT_REFRESH_REMEMBER_ME_EXPIRES_IN':
            return '30d';
          case 'JWT_REFRESH_EXPIRES_IN':
            return '7d';
        }
        return 'test-secret';
      });

      mockJwtService.signAsync.mockResolvedValue('token');

      await authService.generateTokens(userId, email, roles, true);

      expect(mockJwtService.signAsync).toHaveBeenNthCalledWith(
        2,
        expect.any(Object),
        expect.objectContaining({
          expiresIn: '30d',
        }),
      );
    });

    it('should throw error when JWT secrets are missing', async () => {
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'JWT_SECRET' || key === 'JWT_REFRESH_SECRET') return null;
        return 'other-value';
      });

      await expect(
        authService.generateTokens('user-id', 'email', []),
      ).rejects.toThrow(Error);
    });
  });

  describe('loginWithBackupCode', () => {
    it('should login successfully with valid backup code', async () => {
      const tempToken = 'temp-token';
      const backupCode = 'ABCD1234';

      // Use the mocked hash format for backup codes
      const mockUser = {
        id: 'user-id',
        email: 'test@example.com',
        isTwoFactorEnabled: true,
        backupCodes: [
          'hashed_ABCD1234', // Use mocked bcrypt hash format
          'hashed_EFGH5678',
        ],
      };

      mockJwtService.verifyAsync.mockResolvedValue({ sub: mockUser.id });
      mockUsersService.findById.mockResolvedValue(mockUser);
      mockUsersService.update.mockResolvedValue({});

      // Override bcrypt.compare to return true for the valid code and false for others
      const bcryptMock = require('bcryptjs');
      bcryptMock.compare.mockImplementation((code, hash) => {
        if (code === 'ABCD1234' && hash === 'hashed_ABCD1234') {
          return Promise.resolve(true);
        }
        if (code === 'EFGH5678' && hash === 'hashed_EFGH5678') {
          return Promise.resolve(true);
        }
        return Promise.resolve(false);
      });

      mockJwtService.signAsync.mockResolvedValue('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('refresh-token');
      mockPrismaService.authProvider.findFirst.mockResolvedValue({
        provider: 'LOCAL',
      });

      const result = await authService.loginWithBackupCode(
        tempToken,
        backupCode,
      );

      expect(result.user.email).toBe(mockUser.email);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(mockUsersService.update).toHaveBeenCalled();
    });

    it('should throw unauthorized for invalid backup code format', async () => {
      const tempToken = 'temp-token';
      const invalidBackupCode = '123'; // Too short

      mockJwtService.verifyAsync.mockResolvedValue({ sub: 'user-id' });

      await expect(
        authService.loginWithBackupCode(tempToken, invalidBackupCode),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw unauthorized for user without 2FA', async () => {
      const tempToken = 'temp-token';
      const backupCode = 'ABCD1234';

      const mockUser = {
        id: 'user-id',
        email: 'test@example.com',
        isTwoFactorEnabled: false,
      };

      mockJwtService.verifyAsync.mockResolvedValue({ sub: mockUser.id });
      mockUsersService.findById.mockResolvedValue(mockUser);

      await expect(
        authService.loginWithBackupCode(tempToken, backupCode),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('emailVerification', () => {
    describe('generateEmailVerificationToken', () => {
      it('should generate email verification token', async () => {
        const email = 'test@example.com';

        mockJwtService.signAsync.mockResolvedValue('verification-token');

        const result = await authService.generateEmailVerificationToken(email);

        expect(typeof result).toBe('string');
        expect(result).toBe('verification-token');
        expect(mockJwtService.signAsync).toHaveBeenCalledWith(
          expect.objectContaining({
            email,
            type: 'verification',
            sub: email,
          }),
          expect.objectContaining({
            secret: expect.any(String),
            expiresIn: '24h',
          }),
        );
      });

      it('should throw InternalServerErrorException when JWT_SECRET is missing', async () => {
        mockConfigService.get.mockReturnValue(null);

        await expect(
          authService.generateEmailVerificationToken('test@example.com'),
        ).rejects.toThrow(InternalServerErrorException);
      });
    });

    describe('resendVerificationEmail', () => {
      it('should resend verification email successfully', async () => {
        const email = 'test@example.com';

        const mockUser = {
          id: 'user-id',
          email,
          isEmailVerified: false,
        };

        mockUsersService.findByEmail.mockResolvedValue(mockUser);
        mockJwtService.signAsync.mockResolvedValue('new-token');
        mockUsersService.update.mockResolvedValue({});

        await authService.resendVerificationEmail(email);

        expect(mockUsersService.findByEmail).toHaveBeenCalledWith(email);
        expect(mockUsersService.update).toHaveBeenCalled();
      });

      it('should throw NotFoundException for non-existent user', async () => {
        mockUsersService.findByEmail.mockResolvedValue(null);

        await expect(
          authService.resendVerificationEmail('nonexistent@example.com'),
        ).rejects.toThrow(NotFoundException);
      });

      it('should throw BadRequestException for already verified email', async () => {
        const mockUser = {
          id: 'user-id',
          email: 'verified@example.com',
          isEmailVerified: true,
        };

        mockUsersService.findByEmail.mockResolvedValue(mockUser);

        await expect(
          authService.resendVerificationEmail('verified@example.com'),
        ).rejects.toThrow(BadRequestException);
      });
    });
  });

  describe('providerManagement', () => {
    describe('getUserProviders', () => {
      it('should return user auth providers', async () => {
        const userId = 'user-id';

        const mockProviders = [
          {
            id: '1',
            provider: 'LOCAL',
            email: 'test@example.com',
            isPrimary: true,
            linkedAt: new Date(),
            lastUsedAt: new Date(),
          },
          {
            id: '2',
            provider: 'GOOGLE',
            email: 'test@gmail.com',
            isPrimary: false,
            linkedAt: new Date(),
            lastUsedAt: new Date(),
          },
        ];

        mockPrismaService.authProvider.findMany.mockResolvedValue(
          mockProviders,
        );

        const result = await authService.getUserProviders(userId);

        expect(mockPrismaService.authProvider.findMany).toHaveBeenCalledWith({
          where: { userId },
          select: expect.any(Object),
          orderBy: { linkedAt: 'asc' },
        });
        expect(result).toEqual(mockProviders);
      });
    });

    describe('setPrimaryProvider', () => {
      it('should set provider as primary successfully', async () => {
        const userId = 'user-id';
        const provider = 'GOOGLE';

        mockPrismaService.authProvider.updateMany.mockResolvedValue({
          count: 1,
        });
        mockPrismaService.authProvider.updateMany.mockResolvedValueOnce({
          count: 1,
        });
        mockPrismaService.authProvider.updateMany.mockResolvedValueOnce({
          count: 1,
        });

        await authService.setPrimaryProvider(userId, provider);

        expect(mockPrismaService.authProvider.updateMany).toHaveBeenCalledWith({
          where: { userId },
          data: { isPrimary: false },
        });
        expect(mockPrismaService.authProvider.updateMany).toHaveBeenCalledWith({
          where: { userId, provider },
          data: { isPrimary: true },
        });
      });
    });

    describe('unlinkProvider', () => {
      it('should unlink provider successfully', async () => {
        const userId = 'user-id';
        const provider = 'GOOGLE';

        const mockUser = {
          id: userId,
          password: 'hashed-password',
        };

        const mockProvider = {
          id: 'provider-id',
          isPrimary: false,
        };

        mockUsersService.findById.mockResolvedValue(mockUser);
        mockPrismaService.authProvider.findUnique.mockResolvedValue(
          mockProvider,
        );
        mockPrismaService.authProvider.findFirst.mockResolvedValue({
          provider: 'LOCAL',
        });

        await authService.unlinkProvider(userId, provider);

        expect(mockPrismaService.authProvider.delete).toHaveBeenCalledWith({
          where: { id: mockProvider.id },
        });
      });

      it('should throw BadRequestException when unlinking only provider without password', async () => {
        const userId = 'user-id';
        const provider = 'GOOGLE';

        const mockUser = {
          id: userId,
          password: null,
        };

        const mockProvider = {
          id: 'provider-id',
          isPrimary: false,
        };

        mockUsersService.findById.mockResolvedValue(mockUser);
        mockPrismaService.authProvider.findUnique.mockResolvedValue(
          mockProvider,
        );
        mockPrismaService.authProvider.count.mockResolvedValue(1);

        await expect(
          authService.unlinkProvider(userId, provider),
        ).rejects.toThrow(BadRequestException);
      });

      it('should set new primary provider when unlinking primary provider', async () => {
        const userId = 'user-id';
        const provider = 'GOOGLE';

        const mockUser = {
          id: userId,
          password: 'hashed-password',
        };

        const mockProvider = {
          id: 'provider-id',
          isPrimary: true,
          provider: 'GOOGLE',
        };

        const remainingProvider = {
          provider: 'GITHUB',
          id: 'github-id',
        };

        mockUsersService.findById.mockResolvedValue(mockUser);
        mockPrismaService.authProvider.findUnique.mockResolvedValue(
          mockProvider,
        );
        mockPrismaService.authProvider.count.mockResolvedValue(2);
        mockPrismaService.authProvider.findFirst.mockResolvedValue(
          remainingProvider,
        );

        await authService.unlinkProvider(userId, provider);

        expect(mockPrismaService.authProvider.updateMany).toHaveBeenCalledWith({
          where: { userId, provider: remainingProvider.provider },
          data: { isPrimary: true },
        });
      });

      it('should throw NotFoundException when provider is not linked', async () => {
        mockPrismaService.authProvider.findUnique.mockResolvedValue(null);

        await expect(
          authService.unlinkProvider('user-id', 'GOOGLE'),
        ).rejects.toThrow(NotFoundException);
      });
    });
  });

  describe('generateGTMPermissionToken', () => {
    it('should generate GTM permission token successfully', async () => {
      const userId = 'user-id';
      const context = { projectId: 'project-123' };

      const mockUser = {
        id: userId,
        email: 'test@example.com',
      };

      const mockGoogleProvider = {
        accessToken: 'google-access-token',
      };

      mockUsersService.findById.mockResolvedValue(mockUser);
      mockPrismaService.authProvider.findFirst.mockResolvedValue(
        mockGoogleProvider,
      );
      mockJwtService.signAsync.mockResolvedValue('gtm-permission-token');

      const result = await authService.generateGTMPermissionToken(
        userId,
        context,
      );

      expect(result).toHaveProperty('permissionToken');
      expect(result).toHaveProperty('expiresIn');
      expect(result).toHaveProperty('issuedAt');
      expect(mockJwtService.signAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: userId,
          email: mockUser.email,
          type: 'gtm-permission',
          permissions: expect.any(Array),
          context,
        }),
        expect.objectContaining({
          secret: expect.any(String),
          expiresIn: '15m',
          audience: 'stargate-gtm',
          issuer: 'stargate-auth',
        }),
      );
    });

    it('should generate token without context if not provided', async () => {
      const userId = 'user-id';

      const mockUser = {
        id: userId,
        email: 'test@example.com',
      };

      const mockGoogleProvider = {
        accessToken: 'google-access-token',
      };

      mockUsersService.findById.mockResolvedValue(mockUser);
      mockPrismaService.authProvider.findFirst.mockResolvedValue(
        mockGoogleProvider,
      );
      mockJwtService.signAsync.mockResolvedValue('token-without-context');

      const result = await authService.generateGTMPermissionToken(userId);

      expect(result.permissionToken).toBeDefined();
      expect(mockJwtService.signAsync).toHaveBeenCalledWith(
        expect.not.objectContaining({ context: expect.anything() }),
        expect.any(Object),
      );
    });

    it('should throw UnauthorizedException when user not found', async () => {
      mockUsersService.findById.mockResolvedValue(null);

      await expect(
        authService.generateGTMPermissionToken('non-existent-user'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw UnauthorizedException when Google auth not configured', async () => {
      const mockUser = {
        id: 'user-id',
        email: 'test@example.com',
      };

      mockUsersService.findById.mockResolvedValue(mockUser);
      mockPrismaService.authProvider.findFirst.mockResolvedValue(null);

      await expect(
        authService.generateGTMPermissionToken('user-id'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should include correct GTM permissions in token', async () => {
      const userId = 'user-id';

      const mockUser = {
        id: userId,
        email: 'test@example.com',
      };

      const mockGoogleProvider = {
        accessToken: 'google-access-token',
      };

      mockUsersService.findById.mockResolvedValue(mockUser);
      mockPrismaService.authProvider.findFirst.mockResolvedValue(
        mockGoogleProvider,
      );
      mockJwtService.signAsync.mockResolvedValue('token');

      const result = await authService.generateGTMPermissionToken(userId);

      expect(mockJwtService.signAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          permissions: expect.arrayContaining([
            'gtm.accounts.read',
            'gtm.containers.read',
            'gtm.tags.read',
          ]),
        }),
        expect.any(Object),
      );
    });
  });

  describe('facebookLogin', () => {
    it('should complete Facebook OAuth login successfully', async () => {
      const mockFacebookUser = {
        email: 'facebook@example.com',
        name: 'Facebook User',
        picture: 'https://avatar.facebook.com/photo.jpg',
        facebookId: 'facebook-123',
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      };

      const mockValidatedUser = {
        id: 'user-id',
        email: mockFacebookUser.email,
        name: mockFacebookUser.name,
        isTwoFactorEnabled: false,
      };

      mockUsersService.findByEmail.mockResolvedValue(mockValidatedUser);
      mockJwtService.signAsync.mockResolvedValue('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('refresh-token');
      mockPrismaService.authProvider.findFirst.mockResolvedValue({
        provider: 'FACEBOOK',
      });

      const result = await authService.facebookLogin(mockFacebookUser);

      expect(result.user.email).toBe(mockFacebookUser.email);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });
  });

  describe('githubLogin', () => {
    it('should complete GitHub OAuth login successfully', async () => {
      const mockGithubUser = {
        email: 'github@example.com',
        name: 'Github User',
        avatar: 'https://avatar.github.com/photo.jpg',
        githubId: 'github-123',
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        username: 'githubuser',
      };

      const mockValidatedUser = {
        id: 'user-id',
        email: mockGithubUser.email,
        name: mockGithubUser.name,
        isTwoFactorEnabled: false,
      };

      mockUsersService.findByEmail.mockResolvedValue(mockValidatedUser);
      mockJwtService.signAsync.mockResolvedValue('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('access-token');
      mockJwtService.signAsync.mockResolvedValueOnce('refresh-token');
      mockPrismaService.authProvider.findFirst.mockResolvedValue({
        provider: 'GITHUB',
      });

      const result = await authService.githubLogin(mockGithubUser);

      expect(result.user.email).toBe(mockGithubUser.email);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });
  });

  describe('verifyTwoFactorCode', () => {
    it('should verify valid 2FA code successfully', async () => {
      const userId = 'user-id';
      const validCode = '123456';

      const mockUser = {
        id: userId,
        email: 'test@example.com',
        twoFactorSecret: 'JBSWY3DPEHPK3PXP',
      };

      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      const result = await authService.verifyTwoFactorCode(userId, validCode);

      expect(result).toBe(true);
    });

    it('should return false for user without 2FA secret', async () => {
      const userId = 'user-id';
      const code = '123456';

      const mockUser = {
        id: userId,
        email: 'test@example.com',
        twoFactorSecret: null,
      };

      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      const result = await authService.verifyTwoFactorCode(userId, code);

      expect(result).toBe(false);
    });

    it('should return false for invalid code format', async () => {
      const userId = 'user-id';
      const invalidCode = 'abc123'; // Contains letters

      const result = await authService.verifyTwoFactorCode(userId, invalidCode);

      expect(result).toBe(false);
    });

    it('should return false when user not found', async () => {
      const userId = 'user-id';
      const code = '123456';

      mockPrismaService.user.findUnique.mockResolvedValue(null);

      const result = await authService.verifyTwoFactorCode(userId, code);

      expect(result).toBe(false);
    });
  });

  describe('getTwoFactorStatus', () => {
    it('should return 2FA status for user', async () => {
      const userId = 'user-id';

      const mockUser = {
        id: userId,
        email: 'test@example.com',
        isTwoFactorEnabled: true,
        twoFactorSecret: 'secret-key',
      };

      mockUsersService.findById.mockResolvedValue(mockUser);

      const result = await authService.getTwoFactorStatus(userId);

      expect(result).toEqual({
        isEnabled: true,
        hasSecret: true,
      });
    });

    it('should return disabled status when 2FA is not enabled', async () => {
      const userId = 'user-id';

      const mockUser = {
        id: userId,
        email: 'test@example.com',
        isTwoFactorEnabled: false,
        twoFactorSecret: null,
      };

      mockUsersService.findById.mockResolvedValue(mockUser);

      const result = await authService.getTwoFactorStatus(userId);

      expect(result).toEqual({
        isEnabled: false,
        hasSecret: false,
      });
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
      // Store original mock implementation
      const originalGetMock = mockConfigService.get.getMockImplementation();

      try {
        // Temporarily override config to trigger secret validation error
        mockConfigService.get.mockImplementation((key: string) => {
          if (key === 'JWT_SECRET') return 'short';
          return null;
        });

        process.env.TEST_NAME = 'JWT secret validation error test';

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
      } finally {
        // Explicitly restore original mock implementation
        mockConfigService.get.mockImplementation(originalGetMock);
        delete process.env.TEST_NAME;
      }
    });
  });
});
