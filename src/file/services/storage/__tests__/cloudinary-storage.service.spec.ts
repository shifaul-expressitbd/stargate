/**
 * Cloudinary Storage Service Tests
 * Tests the Cloudinary storage implementation for image/media files
 */

import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { MulterFile } from '../../../interfaces/file-options.interface';
import { CloudinaryStorageOptions } from '../../../interfaces/storage-options.interface';
import { StorageProvider } from '../../../interfaces/storage.interface';
import { CloudinaryStorageService } from '../cloudinary-storage.service';

// Mock Cloudinary
jest.mock('cloudinary', () => require('../../../../test/__mocks__/cloudinary'));

const mockCloudinary = require('cloudinary');

// Mock ConfigService
const mockConfigService = {
    get: jest.fn(),
};

describe('CloudinaryStorageService', () => {
    let service: CloudinaryStorageService;
    let configService: ConfigService;

    const mockOptions: CloudinaryStorageOptions = {
        provider: StorageProvider.CLOUDINARY,
        cloudName: 'test-cloud',
        apiKey: 'test-api-key',
        apiSecret: 'test-api-secret',
        folder: 'test-folder',
        secure: true,
    };

    const mockMulterFile: MulterFile = {
        fieldname: 'file',
        originalname: 'test-image.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 1024000,
        destination: '/tmp',
        filename: 'test-image.jpg',
        path: '/tmp/test-image.jpg',
        buffer: Buffer.from('test image content'),
    };

    const mockBuffer = Buffer.from('test buffer content');

    beforeEach(async () => {
        // Reset all mocks
        jest.clearAllMocks();

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
                {
                    provide: CloudinaryStorageService,
                    useFactory: (configService: ConfigService) =>
                        new CloudinaryStorageService(mockOptions, configService),
                    inject: [ConfigService],
                },
            ],
        }).compile();

        service = module.get<CloudinaryStorageService>(CloudinaryStorageService);
        configService = module.get<ConfigService>(ConfigService);
    });

    describe('Initialization', () => {
        it('should be defined', () => {
            expect(service).toBeDefined();
        });

        it('should have correct provider', () => {
            expect(service['provider']).toBe(StorageProvider.CLOUDINARY);
        });

        it('should configure Cloudinary on initialization', () => {
            expect(mockCloudinary.v2.config).toHaveBeenCalledWith({
                cloud_name: mockOptions.cloudName,
                api_key: mockOptions.apiKey,
                api_secret: mockOptions.apiSecret,
                secure: mockOptions.secure,
            });
        });
    });

    describe('Upload Operations', () => {
        describe('Buffer Upload', () => {
            it('should upload buffer successfully', async () => {
                const result = await service.upload(mockBuffer, 'test-key');

                expect(result).toEqual({
                    fileId: 'test_public_id',
                    key: 'test_public_id',
                    url: 'https://res.cloudinary.com/test/image/upload/test.jpg',
                    metadata: {
                        size: 1024000,
                        mimeType: 'image/jpg',
                        filename: 'test.jpg',
                        uploadedAt: expect.any(Date),
                    },
                    providerMetadata: {
                        width: 1920,
                        height: 1080,
                        format: 'jpg',
                        resource_type: 'image',
                        version: 1234567891,
                    },
                    success: true,
                });

                expect(mockCloudinary.v2.uploader.upload_stream).toHaveBeenCalledWith(
                    expect.objectContaining({
                        public_id: 'test-key',
                        folder: mockOptions.folder,
                        resource_type: 'raw',
                    }),
                    expect.any(Function)
                );
            });
        });

        describe('MulterFile Upload', () => {
            it('should upload MulterFile successfully', async () => {
                const result = await service.upload(mockMulterFile, 'custom-key');

                expect(result).toEqual({
                    fileId: 'test_public_id',
                    key: 'test_public_id',
                    url: 'https://res.cloudinary.com/test/image/upload/test.jpg',
                    metadata: {
                        size: 1024000,
                        mimeType: 'image/jpg',
                        filename: 'test.jpg',
                        uploadedAt: expect.any(Date),
                    },
                    providerMetadata: {
                        width: 1920,
                        height: 1080,
                        format: 'jpg',
                        resource_type: 'image',
                        version: 1234567891,
                    },
                    success: true,
                });

                expect(mockCloudinary.v2.uploader.upload).toHaveBeenCalledWith(
                    mockMulterFile.path,
                    expect.objectContaining({
                        public_id: 'custom-key',
                        folder: mockOptions.folder,
                        resource_type: 'image',
                    }),
                    expect.any(Function)
                );
            });

            it('should handle different resource types', async () => {
                const videoFile = { ...mockMulterFile, mimetype: 'video/mp4' };
                await service.upload(videoFile, 'video-key');

                expect(mockCloudinary.v2.uploader.upload).toHaveBeenCalledWith(
                    expect.any(String),
                    expect.objectContaining({
                        resource_type: 'video',
                    }),
                    expect.any(Function)
                );
            });
        });

        it('should add custom metadata', async () => {
            const customMetadata = { alt: 'Test image', caption: 'A test image' };

            await service.upload(mockMulterFile, 'test-key', {
                metadata: customMetadata,
            });

            expect(mockCloudinary.v2.uploader.upload).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    context: customMetadata,
                }),
                expect.any(Function)
            );
        });

        it('should handle upload errors', async () => {
            mockCloudinary.v2.uploader.upload.mockImplementationOnce(
                (path, options, callback) => callback(new Error('Upload failed'), null)
            );

            const result = await service.upload(mockMulterFile, 'test-key');

            expect(result).toEqual({
                fileId: '',
                key: '',
                url: '',
                metadata: {
                    size: 0,
                    mimeType: '',
                    filename: '',
                    uploadedAt: expect.any(Date),
                },
                success: false,
                error: 'Upload failed',
            });
        });
    });

    describe('Download Operations', () => {
        it('should return optimized URL for download', async () => {
            const result = await service.download('test-key');

            expect(result).toEqual({
                stream: undefined,
                metadata: {
                    size: 0,
                    mimeType: 'application/pdf',
                    lastModified: expect.any(Date),
                },
                success: true,
            });

            expect(mockCloudinary.v2.url).toHaveBeenCalledWith('test-key', {
                secure: true,
                quality: 'auto',
                fetch_format: 'auto',
            });
        });

        it('should handle download errors', async () => {
            mockCloudinary.v2.url.mockImplementationOnce(() => {
                throw new Error('URL generation failed');
            });

            const result = await service.download('test-key');

            expect(result).toEqual({
                success: false,
                error: 'URL generation failed',
            });
        });
    });

    describe('Delete Operations', () => {
        it('should delete file successfully', async () => {
            const result = await service.delete('test-key');

            expect(result).toEqual({ success: true });
            expect(mockCloudinary.v2.uploader.destroy).toHaveBeenCalledWith(
                'test-key',
                expect.any(Function)
            );
        });

        it('should handle delete errors', async () => {
            mockCloudinary.v2.uploader.destroy.mockImplementationOnce(
                (key, callback) => callback(new Error('Delete failed'), null)
            );

            const result = await service.delete('test-key');

            expect(result).toEqual({
                success: false,
                error: 'Delete failed',
            });
        });
    });

    describe('Exists Operations', () => {
        it('should check file existence successfully', async () => {
            const result = await service.exists('test-key');

            expect(result).toEqual({
                exists: true,
                metadata: {
                    size: 1024000,
                    mimeType: 'image/jpg',
                    lastModified: expect.any(Date),
                },
            });

            expect(mockCloudinary.v2.api.resource).toHaveBeenCalledWith(
                'test-key',
                expect.any(Function)
            );
        });

        it('should handle file not found', async () => {
            mockCloudinary.v2.api.resource.mockImplementationOnce(
                (key, callback) => callback(new Error('Not found'), null)
            );

            const result = await service.exists('nonexistent-key');

            expect(result).toEqual({ exists: false });
        });
    });

    describe('URL Generation', () => {
        it('should generate URL without options', async () => {
            const result = await service.getUrl('test-key');

            expect(result).toEqual({
                url: 'https://res.cloudinary.com/test/image/upload/test.jpg',
                success: true,
            });

            expect(mockCloudinary.v2.url).toHaveBeenCalledWith('test-key', {
                secure: true,
                quality: 'auto',
                fetch_format: 'auto',
            });
        });

        it('should generate download URL', async () => {
            const result = await service.getUrl('test-key', { download: true });

            expect(mockCloudinary.v2.url).toHaveBeenCalledWith('test-key', {
                secure: true,
                quality: 'auto',
                fetch_format: 'auto',
                flags: 'attachment',
            });
        });

        it('should handle URL generation errors', async () => {
            mockCloudinary.v2.url.mockImplementationOnce(() => {
                throw new Error('URL generation failed');
            });

            const result = await service.getUrl('test-key');

            expect(result).toEqual({
                url: '',
                success: false,
                error: 'URL generation failed',
            });
        });
    });

    describe('Copy Operations', () => {
        it('should copy file using rename', async () => {
            const result = await service.copy('source-key', 'dest-key');

            expect(result).toEqual({ success: true });
            expect(mockCloudinary.v2.uploader.rename).toHaveBeenCalledWith(
                'source-key',
                'dest-key',
                expect.any(Function)
            );
        });

        it('should handle copy errors', async () => {
            mockCloudinary.v2.uploader.rename.mockImplementationOnce(
                (from, to, callback) => callback(new Error('Copy failed'), null)
            );

            const result = await service.copy('source-key', 'dest-key');

            expect(result).toEqual({
                success: false,
                error: 'Copy failed',
            });
        });
    });

    describe('List Operations', () => {
        it('should list files successfully', async () => {
            const result = await service.list('test-prefix');

            expect(result).toEqual({
                files: [
                    {
                        key: 'test_public_id',
                        size: 1024000,
                        lastModified: expect.any(Date),
                        mimeType: 'image/jpg',
                    },
                ],
                continuationToken: null,
                truncated: false,
            });

            expect(mockCloudinary.v2.api.resources).toHaveBeenCalledWith(
                expect.objectContaining({
                    type: 'upload',
                    prefix: 'test-prefix',
                    max_results: 100,
                }),
                expect.any(Function)
            );
        });

        it('should handle pagination', async () => {
            mockCloudinary.v2.api.resources.mockImplementationOnce(
                (options, callback) => callback(null, {
                    resources: [],
                    next_cursor: 'next-page-token',
                })
            );

            const result = await service.list();

            expect(result.truncated).toBe(true);
            expect(result.continuationToken).toBe('next-page-token');
        });

        it('should handle list errors', async () => {
            mockCloudinary.v2.api.resources.mockImplementationOnce(
                (options, callback) => callback(new Error('List failed'), null)
            );

            const result = await service.list();

            expect(result).toEqual({
                files: [],
                truncated: false,
            });
        });
    });

    describe('Metadata Operations', () => {
        it('should get file metadata', async () => {
            const result = await service.getMetadata('test-key');

            expect(result).toEqual({
                size: 1024000,
                mimeType: 'image/jpg',
                lastModified: expect.any(Date),
                etag: '"1234567891"',
                customMetadata: undefined,
            });

            expect(mockCloudinary.v2.api.resource).toHaveBeenCalledWith(
                'test-key',
                expect.any(Function)
            );
        });

        it('should return null for nonexistent file', async () => {
            mockCloudinary.v2.api.resource.mockImplementationOnce(
                (key, callback) => callback(new Error('Not found'), null)
            );

            const result = await service.getMetadata('nonexistent-key');

            expect(result).toBeNull();
        });

        it('should update metadata', async () => {
            const metadata = { alt: 'Updated alt text' };
            const result = await service.updateMetadata('test-key', metadata);

            expect(result).toEqual({ success: true });
            expect(mockCloudinary.v2.uploader.update_metadata).toHaveBeenCalledWith(
                metadata,
                ['test-key'],
                expect.any(Function)
            );
        });

        it('should handle metadata update errors', async () => {
            mockCloudinary.v2.uploader.update_metadata.mockImplementationOnce(
                (metadata, keys, callback) => callback(new Error('Update failed'), null)
            );

            const result = await service.updateMetadata('test-key', {});

            expect(result).toEqual({
                success: false,
                error: 'Update failed',
            });
        });
    });

    describe('Capabilities', () => {
        it('should return Cloudinary capabilities', () => {
            const capabilities = service.getCapabilities();

            expect(capabilities).toEqual({
                resumableUpload: true,
                signedUrls: false,
                cdnIntegration: true,
                versioning: false,
                customMetadata: true,
                maxFileSize: 100 * 1024 * 1024, // 100MB
                storageClasses: ['standard'],
                features: {
                    imageOptimization: true,
                    formatConversion: true,
                    responsiveImages: true,
                    videoProcessing: true,
                },
            });
        });
    });

    describe('Health Check', () => {
        it('should return healthy when API is accessible', async () => {
            const result = await service['performHealthCheck']();

            expect(result).toBe(true);
            expect(mockCloudinary.v2.api.usage).toHaveBeenCalled();
        });

        it('should return unhealthy when API fails', async () => {
            mockCloudinary.v2.api.usage.mockImplementationOnce(
                (callback) => callback(new Error('API failed'), null)
            );

            const result = await service['performHealthCheck']();

            expect(result).toBe(false);
        });
    });

    describe('Utility Methods', () => {
        it('should determine resource type from MIME type', () => {
            expect(service['getResourceType'](mockBuffer, 'image/jpeg')).toBe('image');
            expect(service['getResourceType'](mockBuffer, 'video/mp4')).toBe('video');
            expect(service['getResourceType'](mockBuffer, 'audio/mpeg')).toBe('video');
            expect(service['getResourceType'](mockBuffer, 'application/pdf')).toBe('raw');
        });

        it('should determine resource type from MulterFile', () => {
            expect(service['getResourceType'](mockMulterFile)).toBe('image');
        });

        it('should generate file key for buffer', () => {
            const key = service['generateFileKey'](mockBuffer);

            expect(key).toContain('buffer');
        });

        it('should generate file key for MulterFile', () => {
            const key = service['generateFileKey'](mockMulterFile);

            expect(key).toContain('test-image.jpg');
        });
    });
});