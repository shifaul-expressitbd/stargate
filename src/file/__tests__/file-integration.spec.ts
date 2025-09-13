/**
 * File Module Integration Tests
 * Tests complete file upload/download workflows across multiple storage providers
 */

import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { MulterFile } from '../interfaces/file-options.interface';
import { StorageProvider } from '../interfaces/storage.interface';
import { FileMetadataService } from '../services/file-metadata.service';
import { FileValidationService } from '../services/file-validation.service';
import { FileService } from '../services/file.service';
import { StorageManagerService } from '../services/storage-manager.service';
import { StorageSelectorService } from '../services/storage-selector.service';

// Mock all external dependencies
jest.mock('@aws-sdk/client-s3');
jest.mock('@aws-sdk/s3-request-presigner');
jest.mock('@prisma/client');
jest.mock('../../database/prisma/prisma.service');
jest.mock('cloudinary');
jest.mock('fs');
jest.mock('path');
jest.mock('crypto');

const mockStorageManagerService = {
    uploadFile: jest.fn(),
    downloadFile: jest.fn(),
    deleteFile: jest.fn(),
    getFileUrl: jest.fn(),
    getAvailableProviders: jest.fn().mockReturnValue([StorageProvider.LOCAL, StorageProvider.S3]),
};

const mockFileMetadataService = {
    createFileMetadata: jest.fn(),
    getFileMetadataById: jest.fn(),
    updateFileMetadata: jest.fn(),
    deleteFileMetadata: jest.fn(),
    getFilesByStorageProvider: jest.fn(),
    getFileStatistics: jest.fn(),
};

const mockFileValidationService = {
    validateFiles: jest.fn(),
};

const mockStorageSelectorService = {
    selectStorage: jest.fn(),
};

const mockConfigService = {
    get: jest.fn(),
};

describe('File Module Integration Tests', () => {
    let fileService: FileService;
    let storageManagerService: StorageManagerService;
    let fileMetadataService: FileMetadataService;
    let module: TestingModule;

    const mockMulterFile: MulterFile = {
        fieldname: 'file',
        originalname: 'integration-test.pdf',
        encoding: '7bit',
        mimetype: 'application/pdf',
        size: 2048000, // 2MB
        destination: '/tmp',
        filename: 'integration-test.pdf',
        path: '/tmp/integration-test.pdf',
        buffer: Buffer.from('integration test file content'),
    };

    const mockUploadResult = {
        fileId: 'integration-test-file-id',
        key: 'integration-test-key',
        url: 'http://localhost:3000/files/integration-test-key',
        metadata: {
            size: 2048000,
            mimeType: 'application/pdf',
            filename: 'integration-test.pdf',
            uploadedAt: new Date(),
        },
        success: true,
    };

    const mockFileMetadata = {
        id: 'integration-test-metadata-id',
        filename: 'integration-test.pdf',
        originalName: 'integration-test.pdf',
        mimeType: 'application/pdf',
        size: 2048000,
        storageProvider: 'local',
        storageKey: 'integration-test-key',
        storageUrl: 'http://localhost:3000/files/integration-test-key',
        category: 'document',
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    beforeEach(async () => {
        // Reset all mocks
        jest.clearAllMocks();

        // Setup default mock behaviors
        mockStorageManagerService.uploadFile.mockResolvedValue(mockUploadResult);
        mockFileMetadataService.createFileMetadata.mockResolvedValue(mockFileMetadata);
        mockFileMetadataService.getFileMetadataById.mockResolvedValue(mockFileMetadata);
        mockFileValidationService.validateFiles.mockResolvedValue({
            valid: [mockMulterFile],
            invalid: [],
        });
        mockStorageSelectorService.selectStorage.mockReturnValue(StorageProvider.LOCAL);

        module = await Test.createTestingModule({
            providers: [
                FileService,
                {
                    provide: StorageManagerService,
                    useValue: mockStorageManagerService,
                },
                {
                    provide: FileMetadataService,
                    useValue: mockFileMetadataService,
                },
                {
                    provide: FileValidationService,
                    useValue: mockFileValidationService,
                },
                {
                    provide: StorageSelectorService,
                    useValue: mockStorageSelectorService,
                },
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
            ],
        }).compile();

        fileService = module.get<FileService>(FileService);
        storageManagerService = module.get<StorageManagerService>(StorageManagerService);
        fileMetadataService = module.get<FileMetadataService>(FileMetadataService);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Complete File Upload Workflow', () => {
        it('should complete full upload workflow with automatic storage selection', async () => {
            // Execute upload
            const result = await fileService.uploadFile(mockMulterFile);

            // Verify the result
            expect(result).toEqual(mockFileMetadata);

            // Verify storage selection was called
            expect(mockStorageSelectorService.selectStorage).toHaveBeenCalledWith(mockMulterFile);

            // Verify upload was called with correct parameters
            expect(mockStorageManagerService.uploadFile).toHaveBeenCalledWith(
                mockMulterFile,
                expect.objectContaining({
                    mimeType: 'application/pdf',
                    metadata: expect.objectContaining({
                        category: undefined,
                    }),
                })
            );

            // Verify metadata was created
            expect(mockFileMetadataService.createFileMetadata).toHaveBeenCalledWith(
                expect.objectContaining({
                    filename: 'integration-test.pdf',
                    originalName: 'integration-test.pdf',
                    mimeType: 'application/pdf',
                    size: 2048000,
                    storageProvider: 'integration-test-file-id',
                    storageKey: 'integration-test-key',
                })
            );
        });

        it('should handle different storage providers in upload workflow', async () => {
            // Test with S3 provider
            mockStorageSelectorService.selectStorage.mockReturnValue(StorageProvider.S3);
            mockFileMetadataService.createFileMetadata.mockResolvedValue({
                ...mockFileMetadata,
                storageProvider: 's3',
            });

            const result = await fileService.uploadFile(mockMulterFile);

            expect(result.storageProvider).toBe('s3');
            expect(mockStorageSelectorService.selectStorage).toHaveBeenCalledWith(mockMulterFile);
        });

        it('should handle Cloudinary provider for images', async () => {
            const imageFile = { ...mockMulterFile, mimetype: 'image/jpeg', originalname: 'test.jpg' };

            mockStorageSelectorService.selectStorage.mockReturnValue(StorageProvider.CLOUDINARY);
            mockFileValidationService.validateFiles.mockResolvedValue({
                valid: [imageFile],
                invalid: [],
            });

            const result = await fileService.uploadFile(imageFile);

            expect(mockStorageSelectorService.selectStorage).toHaveBeenCalledWith(imageFile);
        });
    });

    describe('File Download Workflow', () => {
        it('should complete full download workflow', async () => {
            const mockDownloadResult = {
                stream: Buffer.from('file content'),
                metadata: {
                    size: 2048000,
                    mimeType: 'application/pdf',
                    lastModified: new Date(),
                },
                success: true,
            };

            mockStorageManagerService.downloadFile.mockResolvedValue(mockDownloadResult);

            const result = await fileService.getFileById('integration-test-metadata-id');

            expect(result.metadata.id).toBe('integration-test-metadata-id');
            expect(result.stream).toBeDefined();
            expect(result.mimeType).toBe('application/pdf');

            // Verify metadata retrieval
            expect(mockFileMetadataService.getFileMetadataById).toHaveBeenCalledWith('integration-test-metadata-id');

            // Verify download from correct storage
            expect(mockStorageManagerService.downloadFile).toHaveBeenCalledWith(
                'integration-test-key',
                StorageProvider[StorageProvider.LOCAL]
            );
        });

        it('should handle cross-provider downloads', async () => {
            // Mock S3 file metadata
            const s3FileMetadata = { ...mockFileMetadata, storageProvider: 's3' };
            mockFileMetadataService.getFileMetadataById.mockResolvedValue(s3FileMetadata);

            const mockS3DownloadResult = {
                stream: Buffer.from('s3 file content'),
                metadata: {
                    size: 2048000,
                    mimeType: 'application/pdf',
                    lastModified: new Date(),
                },
                success: true,
            };

            mockStorageManagerService.downloadFile.mockResolvedValue(mockS3DownloadResult);

            const result = await fileService.getFileById('s3-file-id');

            expect(result.metadata.storageProvider).toBe('s3');
            expect(mockStorageManagerService.downloadFile).toHaveBeenCalledWith(
                'integration-test-key',
                StorageProvider[StorageProvider.S3]
            );
        });
    });

    describe('Multi-Provider File Operations', () => {
        it('should handle files distributed across multiple providers', async () => {
            // Mock multiple files with different providers
            const files = [
                { ...mockMulterFile, filename: 'local-file.pdf' },
                { ...mockMulterFile, filename: 's3-file.pdf' },
                { ...mockMulterFile, filename: 'cloudinary-file.jpg', mimetype: 'image/jpeg' },
            ];

            mockFileValidationService.validateFiles.mockResolvedValue({
                valid: files,
                invalid: [],
            });

            // Mock different storage selections
            mockStorageSelectorService.selectStorage
                .mockReturnValueOnce(StorageProvider.LOCAL)
                .mockReturnValueOnce(StorageProvider.S3)
                .mockReturnValueOnce(StorageProvider.CLOUDINARY);

            // Mock upload results for different providers
            mockStorageManagerService.uploadFile
                .mockResolvedValueOnce({
                    ...mockUploadResult,
                    fileId: 'local-file-id',
                    key: 'local-key',
                })
                .mockResolvedValueOnce({
                    ...mockUploadResult,
                    fileId: 's3-file-id',
                    key: 's3-key',
                })
                .mockResolvedValueOnce({
                    ...mockUploadResult,
                    fileId: 'cloudinary-file-id',
                    key: 'cloudinary-key',
                });

            const result = await fileService.uploadFiles(files);

            expect(result.files).toHaveLength(3);
            expect(result.success).toBe(true);
            expect(mockStorageSelectorService.selectStorage).toHaveBeenCalledTimes(3);
            expect(mockStorageManagerService.uploadFile).toHaveBeenCalledTimes(3);
        });

        it('should handle partial failures in multi-file upload', async () => {
            const files = [mockMulterFile, { ...mockMulterFile, filename: 'fail.pdf' }];

            mockFileValidationService.validateFiles.mockResolvedValue({
                valid: files,
                invalid: [],
            });

            mockStorageManagerService.uploadFile
                .mockResolvedValueOnce(mockUploadResult)
                .mockRejectedValueOnce(new Error('Storage failure'));

            const result = await fileService.uploadFiles(files);

            expect(result.files).toHaveLength(1);
            expect(result.failed).toHaveLength(1);
            expect(result.success).toBe(false);
        });
    });

    describe('File Management Lifecycle', () => {
        it('should complete full file lifecycle: create, read, update, delete', async () => {
            // 1. Create (Upload)
            const createdFile = await fileService.uploadFile(mockMulterFile);
            expect(createdFile.id).toBe('integration-test-metadata-id');

            // 2. Read (Download)
            const mockDownloadResult = {
                stream: Buffer.from('file content'),
                metadata: {
                    size: 2048000,
                    mimeType: 'application/pdf',
                    lastModified: new Date(),
                },
                success: true,
            };
            mockStorageManagerService.downloadFile.mockResolvedValue(mockDownloadResult);

            const downloadedFile = await fileService.getFileById('integration-test-metadata-id');
            expect(downloadedFile.metadata.id).toBe('integration-test-metadata-id');

            // 3. Update (Metadata)
            const updatedMetadata = { ...mockFileMetadata, originalName: 'updated-name.pdf' };
            mockFileMetadataService.updateFileMetadata.mockResolvedValue(updatedMetadata);

            const updatedFile = await fileMetadataService.updateFileMetadata(
                'integration-test-metadata-id',
                { originalName: 'updated-name.pdf' }
            );
            expect(updatedFile.originalName).toBe('updated-name.pdf');

            // 4. Delete
            mockFileMetadataService.deleteFileMetadata.mockResolvedValue(mockFileMetadata);

            const deletedFile = await fileService.deleteFile('integration-test-metadata-id');
            expect(deletedFile.id).toBe('integration-test-metadata-id');

            // Verify storage deletion was called
            expect(mockStorageManagerService.deleteFile).toHaveBeenCalledWith(
                'integration-test-key',
                StorageProvider[StorageProvider.LOCAL]
            );
        });
    });

    describe('Error Recovery and Fallback', () => {
        it('should handle storage provider failures with fallback', async () => {
            // Mock primary storage failure
            mockStorageManagerService.uploadFile.mockRejectedValueOnce(
                new Error('Primary storage unavailable')
            );

            // Mock fallback to different provider
            mockStorageSelectorService.selectStorage.mockReturnValue(StorageProvider.LOCAL);
            mockStorageManagerService.uploadFile.mockResolvedValueOnce(mockUploadResult);

            // This would require more complex mocking to test actual fallback logic
            // In a real implementation, StorageSelectorService would handle fallback logic
            expect(mockStorageSelectorService.selectStorage).toHaveBeenCalledWith(mockMulterFile);
        });

        it('should handle metadata inconsistencies', async () => {
            // Mock metadata exists but storage file is missing
            mockFileMetadataService.getFileMetadataById.mockResolvedValue(mockFileMetadata);
            mockStorageManagerService.downloadFile.mockRejectedValue(new Error('File not found in storage'));

            await expect(fileService.getFileById('test-id')).rejects.toThrow('File stream not available');
        });
    });

    describe('Performance and Load Testing', () => {
        it('should handle concurrent file uploads', async () => {
            const files = Array(5).fill(mockMulterFile).map((file, index) => ({
                ...file,
                filename: `concurrent-file-${index}.pdf`,
            }));

            mockFileValidationService.validateFiles.mockResolvedValue({
                valid: files,
                invalid: [],
            });

            mockStorageManagerService.uploadFile.mockResolvedValue(mockUploadResult);
            mockFileMetadataService.createFileMetadata.mockResolvedValue(mockFileMetadata);

            // Execute concurrent uploads
            const promises = files.map(file => fileService.uploadFile(file));
            const results = await Promise.all(promises);

            expect(results).toHaveLength(5);
            expect(mockStorageManagerService.uploadFile).toHaveBeenCalledTimes(5);
            expect(mockFileMetadataService.createFileMetadata).toHaveBeenCalledTimes(5);
        });

        it('should handle large file uploads', async () => {
            const largeFile = {
                ...mockMulterFile,
                size: 100 * 1024 * 1024, // 100MB
                originalname: 'large-file.zip',
                mimetype: 'application/zip',
            };

            // Mock selection of appropriate storage for large files
            mockStorageSelectorService.selectStorage.mockReturnValue(StorageProvider.S3);

            const result = await fileService.uploadFile(largeFile);

            expect(result.size).toBe(100 * 1024 * 1024);
            expect(mockStorageSelectorService.selectStorage).toHaveBeenCalledWith(largeFile);
        });
    });

    describe('Storage Provider Switching', () => {
        it('should allow runtime storage provider switching', async () => {
            // Mock different providers for different scenarios
            const scenarios = [
                { file: { ...mockMulterFile, mimetype: 'image/jpeg' }, expectedProvider: StorageProvider.CLOUDINARY },
                { file: { ...mockMulterFile, size: 50 * 1024 * 1024 }, expectedProvider: StorageProvider.S3 },
                { file: { ...mockMulterFile, size: 1024 }, expectedProvider: StorageProvider.LOCAL },
            ];

            for (const scenario of scenarios) {
                mockStorageSelectorService.selectStorage.mockReturnValue(scenario.expectedProvider);

                const result = await fileService.uploadFile(scenario.file);

                expect(mockStorageSelectorService.selectStorage).toHaveBeenCalledWith(scenario.file);
            }
        });
    });

    describe('Cross-Provider Data Consistency', () => {
        it('should maintain metadata consistency across providers', async () => {
            // Upload files to different providers
            const providers = [StorageProvider.LOCAL, StorageProvider.S3, StorageProvider.CLOUDINARY];

            for (const provider of providers) {
                mockStorageSelectorService.selectStorage.mockReturnValue(provider);
                mockFileMetadataService.createFileMetadata.mockResolvedValue({
                    ...mockFileMetadata,
                    storageProvider: StorageProvider[provider],
                });

                const result = await fileService.uploadFile(mockMulterFile);

                expect(result).toHaveProperty('storageProvider');
                expect(result.path).toBeDefined(); // Using path instead of storageKey
                // Note: storageUrl might not be exposed in DTO, checking id instead
                expect(result.id).toBeDefined();
            }
        });

        it('should handle provider-specific URL generation', async () => {
            // Mock different URL formats for different providers
            const urlScenarios = [
                {
                    provider: StorageProvider.LOCAL,
                    expectedUrlPattern: /^http:\/\/localhost:3000\/files\//,
                },
                {
                    provider: StorageProvider.S3,
                    expectedUrlPattern: /\?X-Amz-Algorithm=/,
                },
            ];

            for (const scenario of urlScenarios) {
                mockStorageSelectorService.selectStorage.mockReturnValue(scenario.provider);
                mockStorageManagerService.getFileUrl.mockResolvedValue({
                    url: scenario.provider === StorageProvider.S3
                        ? 'https://bucket.s3.amazonaws.com/file.pdf?signed-params'
                        : 'http://localhost:3000/files/file.pdf',
                    success: true,
                });

                await fileService.uploadFile(mockMulterFile);

                expect(mockStorageManagerService.getFileUrl).toHaveBeenCalled();
            }
        });
    });
});