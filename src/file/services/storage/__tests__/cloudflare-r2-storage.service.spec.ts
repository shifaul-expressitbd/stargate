/**
 * Cloudflare R2 Storage Service Tests
 * Tests the Cloudflare R2 storage implementation
 */

// Mock AWS SDK
jest.mock('@aws-sdk/client-s3');
jest.mock('@aws-sdk/s3-request-presigner');

import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { MulterFile } from '../../../interfaces/file-options.interface';
import { R2StorageOptions } from '../../../interfaces/storage-options.interface';
import { StorageProvider } from '../../../interfaces/storage.interface';
import { CloudflareR2StorageService } from '../cloudflare-r2-storage.service';

const mockS3Client = require('@aws-sdk/client-s3');
const mockGetSignedUrl = require('@aws-sdk/s3-request-presigner');

// Mock fs for file reading
jest.mock('fs', () => ({
    promises: {
        readFile: jest.fn(),
    },
    readFileSync: jest.fn(),
}));

const mockFs = require('fs');

// Mock ConfigService
const mockConfigService = {
    get: jest.fn(),
};

describe('CloudflareR2StorageService', () => {
    let service: CloudflareR2StorageService;
    let configService: ConfigService;

    const mockOptions: R2StorageOptions = {
        provider: StorageProvider.CLOUDFLARE_R2,
        accountId: 'test-account-id',
        accessKeyId: 'test-access-key',
        secretAccessKey: 'test-secret-key',
        bucket: 'test-bucket',
        endpoint: 'https://test-account-id.r2.cloudflarestorage.com',
    };

    const mockMulterFile: MulterFile = {
        fieldname: 'file',
        originalname: 'test-document.pdf',
        encoding: '7bit',
        mimetype: 'application/pdf',
        size: 1024000,
        destination: '/tmp',
        filename: 'test-document.pdf',
        path: '/tmp/test-document.pdf',
        buffer: Buffer.from('test document content'),
    };

    const mockBuffer = Buffer.from('test buffer content');

    beforeEach(async () => {
        // Reset all mocks
        jest.clearAllMocks();

        // Setup default mock implementations
        mockFs.promises.readFile.mockResolvedValue(mockBuffer);
        mockFs.readFileSync.mockReturnValue(mockBuffer);
        mockGetSignedUrl.getSignedUrl.mockImplementation((client, command, options) => {
            const key = command.input.Key;
            return Promise.resolve(`https://mock-r2-bucket.r2.cloudflarestorage.com/${key}?signed-params`);
        });

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
                {
                    provide: CloudflareR2StorageService,
                    useFactory: (configService: ConfigService) =>
                        new CloudflareR2StorageService(mockOptions, configService),
                    inject: [ConfigService],
                },
            ],
        }).compile();

        service = module.get<CloudflareR2StorageService>(CloudflareR2StorageService);
        configService = module.get<ConfigService>(ConfigService);
    });

    describe('Initialization', () => {
        it('should be defined', () => {
            expect(service).toBeDefined();
        });

        it('should have correct provider', () => {
            expect(service['provider']).toBe(StorageProvider.CLOUDFLARE_R2);
        });

        it('should initialize S3 client with correct configuration', () => {
            expect(mockS3Client.S3Client).toHaveBeenCalledWith({
                region: 'auto',
                credentials: {
                    accessKeyId: mockOptions.accessKeyId,
                    secretAccessKey: mockOptions.secretAccessKey,
                },
                endpoint: mockOptions.endpoint,
                forcePathStyle: true,
            });
        });
    });

    describe('Upload Operations', () => {
        describe('Buffer Upload', () => {
            it('should upload buffer successfully', async () => {
                const result = await service.upload(mockBuffer, 'test-key');

                expect(result).toEqual({
                    fileId: expect.any(String),
                    key: 'test-key',
                    url: 'https://mock-r2-bucket.r2.cloudflarestorage.com/test-key?signed-params',
                    metadata: {
                        size: 19, // mockBuffer.length
                        mimeType: 'application/octet-stream',
                        filename: 'test-key',
                        uploadedAt: expect.any(Date),
                    },
                    providerMetadata: {
                        etag: '"mock-etag"',
                        versionId: 'mock-version-id',
                    },
                    success: true,
                });

                expect(mockS3Client.PutObjectCommand).toHaveBeenCalledWith({
                    Bucket: mockOptions.bucket,
                    Key: 'test-key',
                    Body: mockBuffer,
                    ContentType: 'application/octet-stream',
                    ContentLength: 19,
                    Metadata: undefined,
                });
            });
        });

        describe('MulterFile Upload', () => {
            it('should upload MulterFile successfully', async () => {
                const result = await service.upload(mockMulterFile, 'custom-key');

                expect(result).toEqual({
                    fileId: expect.any(String),
                    key: 'custom-key',
                    url: 'https://mock-r2-bucket.r2.cloudflarestorage.com/custom-key?signed-params',
                    metadata: {
                        size: 1024000,
                        mimeType: 'application/pdf',
                        filename: 'custom-key',
                        uploadedAt: expect.any(Date),
                    },
                    providerMetadata: {
                        etag: '"mock-etag"',
                        versionId: 'mock-version-id',
                    },
                    success: true,
                });

                expect(mockFs.readFileSync).toHaveBeenCalledWith('/tmp/test-document.pdf');
            });

            it('should use custom MIME type', async () => {
                await service.upload(mockMulterFile, 'test-key', {
                    mimeType: 'application/custom',
                });

                expect(mockS3Client.PutObjectCommand).toHaveBeenCalledWith(
                    expect.objectContaining({
                        ContentType: 'application/custom',
                    })
                );
            });

            it('should include custom metadata', async () => {
                const customMetadata = { category: 'document', owner: 'user123' };

                await service.upload(mockMulterFile, 'test-key', {
                    metadata: customMetadata,
                });

                expect(mockS3Client.PutObjectCommand).toHaveBeenCalledWith(
                    expect.objectContaining({
                        Metadata: customMetadata,
                    })
                );
            });
        });

        it('should handle upload errors', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockRejectedValueOnce(new Error('Upload failed'));

            const result = await service.upload(mockBuffer, 'test-key');

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
        it('should download file successfully', async () => {
            const result = await service.download('test-key');

            expect(result).toEqual({
                stream: 'mock file content',
                metadata: {
                    size: 1024000,
                    mimeType: 'application/octet-stream',
                    lastModified: expect.any(Date),
                },
                success: true,
            });

            expect(mockS3Client.GetObjectCommand).toHaveBeenCalledWith({
                Bucket: mockOptions.bucket,
                Key: 'test-key',
            });
        });

        it('should handle file not found', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockRejectedValueOnce({
                name: 'NoSuchKey',
                message: 'The specified key does not exist.',
            });

            await expect(service.download('nonexistent-key')).rejects.toThrow('File not found');
        });

        it('should handle download errors', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockRejectedValueOnce(new Error('Download failed'));

            const result = await service.download('test-key');

            expect(result).toEqual({
                success: false,
                error: 'Download failed',
            });
        });
    });

    describe('Delete Operations', () => {
        it('should delete file successfully', async () => {
            const result = await service.delete('test-key');

            expect(result).toEqual({ success: true });
            expect(mockS3Client.DeleteObjectCommand).toHaveBeenCalledWith({
                Bucket: mockOptions.bucket,
                Key: 'test-key',
            });
        });

        it('should handle delete errors', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockRejectedValueOnce(new Error('Delete failed'));

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
                    mimeType: 'application/octet-stream',
                    lastModified: expect.any(Date),
                },
            });

            expect(mockS3Client.HeadObjectCommand).toHaveBeenCalledWith({
                Bucket: mockOptions.bucket,
                Key: 'test-key',
            });
        });

        it('should handle file not found', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockRejectedValueOnce({
                name: 'NotFound',
                message: 'Not found',
            });

            const result = await service.exists('nonexistent-key');

            expect(result).toEqual({ exists: false });
        });
    });

    describe('URL Generation', () => {
        it('should generate public URL when configured', async () => {
            const publicOptions = { ...mockOptions, publicUrl: 'https://cdn.example.com' };

            const publicService = new CloudflareR2StorageService(publicOptions, configService);

            const result = await publicService.getUrl('test-key');

            expect(result).toEqual({
                url: 'https://cdn.example.com/test-key',
                success: true,
            });
        });

        it('should generate signed URL when not public', async () => {
            const result = await service.getUrl('test-key');

            expect(result).toEqual({
                url: 'https://mock-r2-bucket.r2.cloudflarestorage.com/test-key?signed-params',
                success: true,
                expiresAt: expect.any(Date),
            });

            expect(mockGetSignedUrl.getSignedUrl).toHaveBeenCalled();
        });

        it('should handle URL generation errors', async () => {
            mockGetSignedUrl.getSignedUrl.mockRejectedValueOnce(new Error('URL generation failed'));

            const result = await service.getUrl('test-key');

            expect(result).toEqual({
                url: '',
                success: false,
                error: 'URL generation failed',
            });
        });
    });

    describe('Copy Operations', () => {
        it('should copy file successfully', async () => {
            const result = await service.copy('source-key', 'dest-key');

            expect(result).toEqual({ success: true });
            expect(mockS3Client.CopyObjectCommand).toHaveBeenCalledWith({
                Bucket: mockOptions.bucket,
                CopySource: `${mockOptions.bucket}/source-key`,
                Key: 'dest-key',
            });
        });

        it('should handle copy errors', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockRejectedValueOnce(new Error('Copy failed'));

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
                        key: 'test-file.txt',
                        size: 1024,
                        lastModified: expect.any(Date),
                        mimeType: undefined,
                    },
                ],
                continuationToken: undefined,
                truncated: false,
            });

            expect(mockS3Client.ListObjectsV2Command).toHaveBeenCalledWith({
                Bucket: mockOptions.bucket,
                Prefix: 'test-prefix',
                MaxKeys: 1000,
                ContinuationToken: undefined,
            });
        });

        it('should handle pagination', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockResolvedValueOnce({
                Contents: [],
                IsTruncated: true,
                NextContinuationToken: 'next-token',
            });

            const result = await service.list();

            expect(result.truncated).toBe(true);
            expect(result.continuationToken).toBe('next-token');
        });

        it('should handle list errors', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockRejectedValueOnce(new Error('List failed'));

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
                mimeType: 'application/octet-stream',
                lastModified: expect.any(Date),
                etag: '"mock-etag"',
                customMetadata: {},
            });

            expect(mockS3Client.HeadObjectCommand).toHaveBeenCalledWith({
                Bucket: mockOptions.bucket,
                Key: 'test-key',
            });
        });

        it('should return null for nonexistent file', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockRejectedValueOnce({
                name: 'NotFound',
            });

            const result = await service.getMetadata('nonexistent-key');

            expect(result).toBeNull();
        });

        it('should update metadata', async () => {
            const metadata = { category: 'updated' };
            const result = await service.updateMetadata('test-key', metadata);

            expect(result).toEqual({ success: true });
            expect(mockS3Client.CopyObjectCommand).toHaveBeenCalledWith({
                Bucket: mockOptions.bucket,
                CopySource: `${mockOptions.bucket}/test-key`,
                Key: 'test-key',
                Metadata: metadata,
                MetadataDirective: 'REPLACE',
            });
        });

        it('should handle metadata update errors', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockRejectedValueOnce(new Error('Update failed'));

            const result = await service.updateMetadata('test-key', {});

            expect(result).toEqual({
                success: false,
                error: 'Update failed',
            });
        });
    });

    describe('Capabilities', () => {
        it('should return R2 capabilities', () => {
            const capabilities = service.getCapabilities();

            expect(capabilities).toEqual({
                resumableUpload: true,
                signedUrls: true,
                cdnIntegration: false,
                versioning: false,
                customMetadata: true,
                maxFileSize: 5 * 1024 * 1024 * 1024 * 1024, // 5TB
                storageClasses: [
                    'STANDARD',
                ],
                features: {
                    lifecycleManagement: false,
                    crossRegionReplication: false,
                    encryptionAtRest: true,
                    globalReplication: true,
                },
            });
        });
    });

    describe('Health Check', () => {
        it('should return healthy when bucket is accessible', async () => {
            const result = await service['performHealthCheck']();

            expect(result).toBe(true);
            expect(mockS3Client.ListObjectsV2Command).toHaveBeenCalledWith({
                Bucket: mockOptions.bucket,
                MaxKeys: 1,
            });
        });

        it('should return unhealthy when bucket access fails', async () => {
            const mockS3ClientInstance = mockS3Client.S3Client.mock.results[0].value;
            mockS3ClientInstance.send.mockRejectedValueOnce(new Error('Access denied'));

            const result = await service['performHealthCheck']();

            expect(result).toBe(false);
        });
    });

    describe('Utility Methods', () => {
        it('should generate file key for buffer', () => {
            const key = service['generateFileKey'](mockBuffer);

            expect(key).toContain('buffer');
        });

        it('should generate file key for MulterFile', () => {
            const key = service['generateFileKey'](mockMulterFile);

            expect(key).toContain('test-document');
        });

        it('should extract filename from key', () => {
            expect(service['extractFilename']('path/to/file.pdf')).toBe('file.pdf');
            expect(service['extractFilename']('file.pdf')).toBe('file.pdf');
        });

        it('should generate presigned URL', async () => {
            const url = await service['generatePresignedUrl']('test-key', 3600);

            expect(url).toBe('https://mock-r2-bucket.r2.cloudflarestorage.com/test-key?signed-params');
            expect(mockGetSignedUrl.getSignedUrl).toHaveBeenCalledWith(
                expect.any(Object),
                expect.any(Object),
                { expiresIn: 3600 }
            );
        });
    });
});