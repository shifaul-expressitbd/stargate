/**
 * Storage Selector Service Tests
 * Tests the intelligent storage provider selection based on file characteristics
 */

import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { FileCategory } from '../../interfaces/file-metadata.interface';
import { MulterFile } from '../../interfaces/file-options.interface';
import { StorageProvider } from '../../interfaces/storage.interface';
import { StorageSelectorService } from '../storage-selector.service';

// Mock ConfigService
const mockConfigService = {
    get: jest.fn().mockReturnValue({
        defaultProvider: StorageProvider.LOCAL,
        providers: {
            [StorageProvider.LOCAL]: { provider: StorageProvider.LOCAL, baseDir: '/tmp' },
            [StorageProvider.CLOUDINARY]: { provider: StorageProvider.CLOUDINARY, cloudName: 'test' },
            [StorageProvider.S3]: { provider: StorageProvider.S3, bucket: 'test' },
        },
    }),
};

describe('StorageSelectorService', () => {
    let service: StorageSelectorService;
    let configService: ConfigService;

    const mockImageFile: MulterFile = {
        fieldname: 'file',
        originalname: 'test-image.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 1024000, // 1MB
        destination: '/tmp',
        filename: 'test-image.jpg',
        path: '/tmp/test-image.jpg',
        buffer: Buffer.from('mock image data'),
    };

    const mockDocumentFile: MulterFile = {
        fieldname: 'file',
        originalname: 'document.pdf',
        encoding: '7bit',
        mimetype: 'application/pdf',
        size: 5120000, // 5MB
        destination: '/tmp',
        filename: 'document.pdf',
        path: '/tmp/document.pdf',
        buffer: Buffer.from('mock document data'),
    };

    const mockLargeFile: MulterFile = {
        fieldname: 'file',
        originalname: 'large-video.mp4',
        encoding: '7bit',
        mimetype: 'video/mp4',
        size: 100 * 1024 * 1024, // 100MB
        destination: '/tmp',
        filename: 'large-video.mp4',
        path: '/tmp/large-video.mp4',
        buffer: Buffer.from('mock video data'),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
                StorageSelectorService,
            ],
        }).compile();

        service = module.get<StorageSelectorService>(StorageSelectorService);
        configService = module.get<ConfigService>(ConfigService);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Initialization', () => {
        it('should be defined', () => {
            expect(service).toBeDefined();
        });

        it('should load storage configuration', () => {
            expect(configService.get).toHaveBeenCalledWith('storage');
        });
    });

    describe('Storage Selection', () => {
        describe('Image Files', () => {
            it('should select Cloudinary for small images', () => {
                const result = service.selectStorage(mockImageFile);

                expect(result).toBe(StorageProvider.CLOUDINARY);
            });

            it('should prefer Cloudinary for images with high performance requirement', () => {
                const result = service.selectStorage(mockImageFile, {
                    performance: 'high',
                });

                expect(result).toBe(StorageProvider.CLOUDINARY);
            });
        });

        describe('Document Files', () => {
            it('should select S3 for documents', () => {
                const result = service.selectStorage(mockDocumentFile);

                expect(result).toBe(StorageProvider.S3);
            });

            it('should select local storage for small documents with cost sensitivity', () => {
                const smallDoc = { ...mockDocumentFile, size: 102400 }; // 100KB

                const result = service.selectStorage(smallDoc, {
                    costSensitivity: 'high',
                });

                expect(result).toBe(StorageProvider.LOCAL);
            });
        });

        describe('Large Files', () => {
            it('should select S3 for large files', () => {
                const result = service.selectStorage(mockLargeFile);

                expect(result).toBe(StorageProvider.S3);
            });

            it('should select S3 for files requiring backup', () => {
                const result = service.selectStorage(mockImageFile, {
                    backupRequired: true,
                });

                expect(result).toBe(StorageProvider.S3);
            });
        });

        describe('Video Files', () => {
            it('should select Cloudinary for videos', () => {
                const result = service.selectStorage(mockLargeFile);

                expect(result).toBe(StorageProvider.CLOUDINARY);
            });
        });

        describe('Archive Files', () => {
            it('should select S3 for archives', () => {
                const archiveFile = {
                    ...mockDocumentFile,
                    mimetype: 'application/zip',
                    originalname: 'archive.zip',
                };

                const result = service.selectStorage(archiveFile);

                expect(result).toBe(StorageProvider.S3);
            });
        });

        describe('Public Access Requirements', () => {
            it('should select Cloudinary for files requiring public access', () => {
                const result = service.selectStorage(mockImageFile, {
                    publicAccess: true,
                });

                expect(result).toBe(StorageProvider.CLOUDINARY);
            });
        });

        describe('Cost Sensitivity', () => {
            it('should select local storage for cost-sensitive small files', () => {
                const smallFile = { ...mockDocumentFile, size: 51200 }; // 50KB

                const result = service.selectStorage(smallFile, {
                    costSensitivity: 'high',
                });

                expect(result).toBe(StorageProvider.LOCAL);
            });
        });

        describe('Global Distribution', () => {
            it('should select S3 for files requiring global distribution', () => {
                const result = service.selectStorage(mockDocumentFile, {
                    globalDistribution: true,
                });

                expect(result).toBe(StorageProvider.S3);
            });
        });
    });

    describe('File Category Detection', () => {
        it('should detect image category', () => {
            const criteria = service['buildCriteria'](mockImageFile);

            expect(criteria.category).toBe(FileCategory.IMAGE);
        });

        it('should detect document category', () => {
            const criteria = service['buildCriteria'](mockDocumentFile);

            expect(criteria.category).toBe(FileCategory.DOCUMENT);
        });

        it('should detect video category', () => {
            const criteria = service['buildCriteria'](mockLargeFile);

            expect(criteria.category).toBe(FileCategory.VIDEO);
        });

        it('should detect archive category', () => {
            const archiveFile = {
                ...mockDocumentFile,
                mimetype: 'application/zip',
                originalname: 'archive.zip',
            };

            const criteria = service['buildCriteria'](archiveFile);

            expect(criteria.category).toBe(FileCategory.ARCHIVE);
        });

        it('should detect other category for unknown types', () => {
            const unknownFile = {
                ...mockDocumentFile,
                mimetype: 'application/x-custom',
                originalname: 'file.custom',
            };

            const criteria = service['buildCriteria'](unknownFile);

            expect(criteria.category).toBe(FileCategory.OTHER);
        });
    });

    describe('Recommendation Engine', () => {
        it('should provide detailed recommendation', () => {
            const criteria = service['buildCriteria'](mockImageFile);
            const recommendation = service.getRecommendation(criteria);

            expect(recommendation).toEqual(
                expect.objectContaining({
                    provider: expect.any(String),
                    reasoning: expect.any(Array),
                    estimatedCostPerGB: expect.any(Number),
                    performance: expect.objectContaining({
                        latency: expect.any(String),
                        throughput: expect.any(String),
                        availability: expect.any(Number),
                    }),
                    compliance: expect.objectContaining({
                        encryption: expect.any(Boolean),
                        auditLogs: expect.any(Boolean),
                        dataResidency: expect.any(Boolean),
                    }),
                })
            );
        });

        it('should include reasoning in recommendations', () => {
            const criteria = service['buildCriteria'](mockImageFile);
            const recommendation = service.getRecommendation(criteria);

            expect(recommendation.reasoning).toContain('Optimized for image processing and delivery');
        });
    });

    describe('Provider Evaluation', () => {
        describe('Local Storage Evaluation', () => {
            it('should score local storage highly for small files', () => {
                const smallFile = { ...mockDocumentFile, size: 102400 }; // 100KB
                const criteria = service['buildCriteria'](smallFile);
                const evaluation = service['evaluateProvider'](StorageProvider.LOCAL, criteria);

                expect(evaluation.score).toBeGreaterThan(25);
                expect(evaluation.reasoning).toContain('Excellent for small files under 100MB');
            });

            it('should score local storage for documents', () => {
                const criteria = service['buildCriteria'](mockDocumentFile);
                const evaluation = service['evaluateProvider'](StorageProvider.LOCAL, criteria);

                expect(evaluation.reasoning).toContain('Well suited for document storage');
            });

            it('should score local storage for local access', () => {
                const criteria = service['buildCriteria'](mockDocumentFile);
                criteria.globalDistribution = false;
                const evaluation = service['evaluateProvider'](StorageProvider.LOCAL, criteria);

                expect(evaluation.reasoning).toContain('Perfect for local/single-region access');
            });
        });

        describe('Cloudinary Evaluation', () => {
            it('should score Cloudinary highly for images', () => {
                const criteria = service['buildCriteria'](mockImageFile);
                const evaluation = service['evaluateProvider'](StorageProvider.CLOUDINARY, criteria);

                expect(evaluation.score).toBeGreaterThan(45);
                expect(evaluation.reasoning).toContain('Optimized for image processing and delivery');
            });

            it('should score Cloudinary for videos', () => {
                const criteria = service['buildCriteria'](mockLargeFile);
                const evaluation = service['evaluateProvider'](StorageProvider.CLOUDINARY, criteria);

                expect(evaluation.score).toBeGreaterThan(35);
                expect(evaluation.reasoning).toContain('Excellent for video storage and streaming');
            });

            it('should score Cloudinary for public access', () => {
                const criteria = service['buildCriteria'](mockImageFile);
                criteria.publicAccess = true;
                const evaluation = service['evaluateProvider'](StorageProvider.CLOUDINARY, criteria);

                expect(evaluation.reasoning).toContain('Built-in CDN for fast global distribution');
            });
        });

        describe('S3 Evaluation', () => {
            it('should score S3 for large files', () => {
                const criteria = service['buildCriteria'](mockLargeFile);
                const evaluation = service['evaluateProvider'](StorageProvider.S3, criteria);

                expect(evaluation.score).toBeGreaterThan(25);
                expect(evaluation.reasoning).toContain('Cost-effective for large files');
            });

            it('should score S3 for backup requirements', () => {
                const criteria = service['buildCriteria'](mockDocumentFile);
                criteria.backupRequired = true;
                const evaluation = service['evaluateProvider'](StorageProvider.S3, criteria);

                expect(evaluation.reasoning).toContain('Excellent for backup and archival');
            });

            it('should score S3 for global distribution', () => {
                const criteria = service['buildCriteria'](mockDocumentFile);
                criteria.globalDistribution = true;
                const evaluation = service['evaluateProvider'](StorageProvider.S3, criteria);

                expect(evaluation.reasoning).toContain('Global distribution capabilities');
            });

            it('should score S3 for long retention', () => {
                const criteria = service['buildCriteria'](mockDocumentFile);
                criteria.retentionDays = 400;
                const evaluation = service['evaluateProvider'](StorageProvider.S3, criteria);

                expect(evaluation.reasoning).toContain('Long-term retention support');
            });
        });
    });

    describe('Provider Availability', () => {
        it('should return available providers', () => {
            const providers = service.getAvailableProviders();

            expect(providers).toEqual(
                expect.arrayContaining([
                    StorageProvider.LOCAL,
                    StorageProvider.CLOUDINARY,
                    StorageProvider.S3,
                ])
            );
        });

        it('should check provider availability', async () => {
            const isAvailable = await service.isProviderAvailable(StorageProvider.LOCAL);

            expect(isAvailable).toBe(true);
        });

        it('should return false for unavailable provider', async () => {
            const isAvailable = await service.isProviderAvailable(StorageProvider.MINIO);

            expect(isAvailable).toBe(false);
        });
    });

    describe('Storage Statistics', () => {
        it('should return storage stats', () => {
            const stats = service.getStorageStats();

            expect(stats).toEqual(
                expect.objectContaining({
                    [StorageProvider.LOCAL]: expect.objectContaining({
                        totalFiles: 0,
                        totalSize: 0,
                        avgFileSize: 0,
                        utilizationRate: 0,
                    }),
                })
            );
        });
    });

    describe('Criteria Building', () => {
        it('should build criteria from file only', () => {
            const criteria = service['buildCriteria'](mockImageFile);

            expect(criteria).toEqual(
                expect.objectContaining({
                    fileSize: mockImageFile.size,
                    mimeType: mockImageFile.mimetype,
                    category: FileCategory.IMAGE,
                    publicAccess: false,
                    retentionDays: 365,
                    costSensitivity: 'medium',
                    performance: 'medium',
                    backupRequired: true,
                    globalDistribution: false,
                })
            );
        });

        it('should merge additional criteria', () => {
            const additionalCriteria = {
                publicAccess: true,
                costSensitivity: 'high' as const,
                globalDistribution: true,
            };

            const criteria = service['buildCriteria'](mockImageFile, additionalCriteria);

            expect(criteria.publicAccess).toBe(true);
            expect(criteria.costSensitivity).toBe('high');
            expect(criteria.globalDistribution).toBe(true);
        });
    });

    describe('Performance Weighting', () => {
        it('should boost score for high-performance requirements', () => {
            const criteria = service['buildCriteria'](mockImageFile);
            criteria.performance = 'high';

            const evaluation = service['evaluateProvider'](StorageProvider.CLOUDINARY, criteria);

            expect(evaluation.reasoning).toContain('Matches high-performance requirements');
        });
    });

    describe('Cost Sensitivity', () => {
        it('should boost score for cost-effective providers', () => {
            const criteria = service['buildCriteria'](mockDocumentFile);
            criteria.costSensitivity = 'high';

            const evaluation = service['evaluateProvider'](StorageProvider.LOCAL, criteria);

            expect(evaluation.reasoning).toContain('Cost-effective option');
        });
    });
});