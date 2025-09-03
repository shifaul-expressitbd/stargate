import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from '../database/prisma/prisma.service';
import { SgtmRegionService } from '../sgtm-region/sgtm-region.service';
import { SgtmContainerService } from './sgtm-container.service';

const mockPrismaService = {
  sgtmContainer: {
    create: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
};

const mockConfigService = {
  get: jest.fn(),
};

const mockHttpService = {
  get: jest.fn(),
  post: jest.fn(),
};

const mockSgtmRegionService = {
  findByKey: jest.fn(),
};

describe('SgtmContainerService', () => {
  let service: SgtmContainerService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SgtmContainerService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: HttpService, useValue: mockHttpService },
        { provide: SgtmRegionService, useValue: mockSgtmRegionService },
      ],
    }).compile();

    service = module.get<SgtmContainerService>(SgtmContainerService);

    // Clear all mocks
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
