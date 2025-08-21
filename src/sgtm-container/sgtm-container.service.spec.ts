import { Test, TestingModule } from '@nestjs/testing';
import { SgtmContainerService } from './sgtm-container.service';

describe('SgtmContainerService', () => {
  let service: SgtmContainerService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SgtmContainerService],
    }).compile();

    service = module.get<SgtmContainerService>(SgtmContainerService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
