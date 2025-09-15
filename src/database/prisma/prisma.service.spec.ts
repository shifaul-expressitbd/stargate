import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from './prisma.service';

describe('PrismaService', () => {
  let service: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [PrismaService],
    }).compile();

    service = module.get<PrismaService>(PrismaService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('onModuleInit', () => {
    it('should connect to the database', async () => {
      const connectSpy = jest.spyOn(service, '$connect');
      await service.onModuleInit();
      expect(connectSpy).toHaveBeenCalled();
    });
  });

  describe('onModuleDestroy', () => {
    it('should disconnect from the database', async () => {
      const disconnectSpy = jest.spyOn(service, '$disconnect');
      await service.onModuleDestroy();
      expect(disconnectSpy).toHaveBeenCalled();
    });
  });

  describe('cleanDatabase', () => {
    it('should throw error when database cleaning is disabled', async () => {
      const originalEnv = process.env.DATABASE_CLEANING_ENABLED;
      process.env.DATABASE_CLEANING_ENABLED = 'false';

      await expect(service.cleanDatabase()).rejects.toThrow(
        'Database cleaning is disabled',
      );

      process.env.DATABASE_CLEANING_ENABLED = originalEnv;
    });
  });
});
