import { Test, TestingModule } from '@nestjs/testing';
import { SgtmContainerController } from './sgtm-container.controller';

describe('SgtmContainerController', () => {
  let controller: SgtmContainerController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SgtmContainerController],
    }).compile();

    controller = module.get<SgtmContainerController>(SgtmContainerController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
