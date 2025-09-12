/**
 * File Service Tests
 * Tests the main file service that orchestrates file operations
 */

import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { MulterFile } from '../../interfaces/file-options.interface';
import { StorageProvider } from '../../interfaces/storage.interface';
import { FileMetadataService } from '../file-metadata.service';
import { FileValidationService } from '../file-validation.service';
import { FileService } from '../file.service';
import { StorageManagerService } from '../storage-manager.service';

// Mock services
const mockStorageManagerService = {
    uploadFile: jest.fn(),
    downloadFile: jest.fn(),
    deleteFile: jest.fn(),
    getFileUrl: jest.fn(),
};

const mockFileMetadataService = {
    createFileMetadata: jest.fn(),
    getFileMetadataById: jest.fn(),
    deleteFileMetadata: jest.fn(),
    getFilesByStorageProvider: jest.fn(),
    getFileStatistics: jest.fn(),
};

const mockFileValidationService = {
    validateFiles: jest.fn(),
};

const mockConfigService = {
    get: jest.fn(),
};

describe('FileService', () => {
    let service: FileService;
    let storageManagerService: StorageManagerService;
    let fileMetadataService: FileMetadataService;
    let fileValidationService: FileValidationService;

    const mockMulterFile: MulterFile = {
        fieldname: 'file',
        originalname: 'test-document.pdf',
        encoding: '7bit',
        mimetype: 'application/pdf',
        size: 1024000,
        destination: '/tmp',
        filename: 'test-document.pdf',
        path: '/tmp/test-document.pdf',
        buffer: Buffer.from('test file content'),
    };

    const mockUploadResult = {
        fileId: 'test-file-id',
        key: 'test-key',
        url: 'http://localhost:3000/files/test-key',
        metadata: {
            size: 1024000,
            mimeType: 'application/pdf',
            filename: 'test-document.pdf',
            uploadedAt: new Date(),
        },
        success: true,
    };

    const mockFileMetadata = {
        id: 'test-metadata-id',
        filename: 'test-document.pdf',
        originalName: 'test-document.pdf',
        mimeType: 'application/pdf',
        size: 1024000,
        storageProvider: 'local',
        storageKey: 'test-key',
        storageUrl: 'http://localhost:3000/files/test-key',
        category: 'document',
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    beforeEach(async () => {
        // Reset all mocks
        jest.clearAllMocks();

        // Setup mock implementations
        mockStorageManagerService.uploadFile.mockResolvedValue(mockUploadResult);
        mockFileMetadataService.createFileMetadata.mockResolvedValue(mockFileMetadata);
        mockFileMetadataService.getFileMetadataById.mockResolvedValue(mockFileMetadata);
        mockFileMetadataService.getFilesByStorageProvider.mockResolvedValue({
            files: [mockFileMetadata],
            total: 1,
            page: 1,
            limit: 20,
            totalPages: 1,
        });
        mockFileValidationService.validateFiles.mockResolvedValue({
            valid: [mockMulterFile],
            invalid: [],
        });

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                FileService,
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
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
            ],
        }).compile();

        service = module.get<FileService>(FileService);
        storageManagerService = module.get<StorageManagerService>(StorageManagerService);
        fileMetadataService = module.get<FileMetadataService>(FileMetadataService);
        fileValidationService = module.get<FileValidationService>(FileValidationService);
    });

    describe('Initialization', () => {
        it('should be defined', () => {
            expect(service).toBeDefined();
        });
    });

    describe('Single File Upload', () => {
        it('should upload single file successfully', async () => {
            const result = await service.uploadFile(mockMulterFile);

            expect(result).toEqual(mockFileMetadata);
            expect(mockStorageManagerService.uploadFile).toHaveBeenCalledWith(
                mockMulterFile,
                expect.objectContaining({
                    mimeType: 'application/pdf',
                    metadata: expect.objectContaining({
                        category: undefined,
                    }),
                })
            );
            expect(mockFileMetadataService.createFileMetadata).toHaveBeenCalledWith(
                expect.objectContaining({
                    filename: 'test-document.pdf',
                    originalName: 'test-document.pdf',
                    mimeType: 'application/pdf',
                    size: 1024000,
                    storageProvider: 'test-file-id',
                    storageKey: 'test-key',
                    storageUrl: 'http://localhost:3000/files/test-key',
                })
            );
        });

        it('should upload file with custom metadata', async () => {
            const metadata = {
                originalName: 'custom-name.pdf',
                category: 'document',
            };

            await service.uploadFile(mockMulterFile, metadata);

            expect(mockStorageManagerService.uploadFile).toHaveBeenCalledWith(
                mockMulterFile,
                expect.objectContaining({
                    mimeType: 'application/pdf',
                    metadata: expect.objectContaining({
                        category: 'document',
                    }),
                })
            );
            expect(mockFileMetadataService.createFileMetadata).toHaveBeenCalledWith(
                expect.objectContaining({
                    originalName: 'custom-name.pdf',
                    category: 'document',
                })
            );
        });

        it('should handle upload errors', async () => {
            mockStorageManagerService.uploadFile.mockRejectedValue(new Error('Upload failed'));

            await expect(service.uploadFile(mockMulterFile)).rejects.toThrow('Upload failed');
        });

        it('should handle metadata creation errors', async () => {
            mockFileMetadataService.createFileMetadata.mockRejectedValue(new Error('Metadata creation failed'));

            await expect(service.uploadFile(mockMulterFile)).rejects.toThrow('Metadata creation failed');
        });
    });

    describe('Multiple File Upload', () => {
        const mockFiles = [mockMulterFile, { ...mockMulterFile, filename: 'test2.pdf' }];

        it('should upload multiple files successfully', async () => {
            const result = await service.uploadFiles(mockFiles);

            expect(result).toEqual({
                files: [mockFileMetadata],
                failed: [],
                totalSize: 1024000,
                duration: expect.any(Number),
                success: true,
            });
            expect(mockFileValidationService.validateFiles).toHaveBeenCalledWith(
                mockFiles,
                {
                    maxSize: 10 * 1024 * 1024,
                    allowedTypes: [],
                }
            );
        });

        it('should handle validation failures', async () => {
            const validationError = {
                file: mockMulterFile,
                error: 'File too large',
            };

            mockFileValidationService.validateFiles.mockResolvedValue({
                valid: [],
                invalid: [validationError],
            });

            const result = await service.uploadFiles(mockFiles);

            expect(result).toEqual({
                files: [],
                failed: [{
                    originalName: 'test-document.pdf',
                    error: 'File too large',
                }],
                totalSize: 0,
                duration: expect.any(Number),
                success: false,
            });
        });

        it('should handle partial upload failures', async () => {
            mockFileValidationService.validateFiles.mockResolvedValue({
                valid: mockFiles,
                invalid: [],
            });

            // Make second upload fail
            mockStorageManagerService.uploadFile
                .mockResolvedValueOnce(mockUploadResult)
                .mockRejectedValueOnce(new Error('Second upload failed'));

            const result = await service.uploadFiles(mockFiles);

            expect(result.files).toHaveLength(1);
            expect(result.failed).toHaveLength(1);
            expect(result.success).toBe(false);
        });

        it('should apply custom validation options', async () => {
            const options = {
                maxSize: 5 * 1024 * 1024,
                allowedTypes: ['application/pdf', 'image/jpeg'],
            };

            await service.uploadFiles(mockFiles, options);

            expect(mockFileValidationService.validateFiles).toHaveBeenCalledWith(
                mockFiles,
                options
            );
        });
    });

    describe('File Download', () => {
        it('should get file by ID successfully', async () => {
            const mockDownloadResult = {
                stream: Buffer.from('file content'),
                metadata: {
                    size: 1024000,
                    mimeType: 'application/pdf',
                    lastModified: new Date(),
                },
                success: true,
            };

            mockStorageManagerService.downloadFile.mockResolvedValue(mockDownloadResult);

            const result = await service.getFileById('test-id');

            expect(result).toEqual({
                metadata: mockFileMetadata,
                stream: Buffer.from('file content'),
                stats: {
                    size: 1024000,
                },
                mimeType: 'application/pdf',
            });
            expect(mockFileMetadataService.getFileMetadataById).toHaveBeenCalledWith('test-id');
            expect(mockStorageManagerService.downloadFile).toHaveBeenCalledWith(
                'test-key',
                StorageProvider[StorageProvider.LOCAL]
            );
        });

        it('should handle file not found', async () => {
            mockFileMetadataService.getFileMetadataById.mockRejectedValue(new Error('File not found'));

            await expect(service.getFileById('nonexistent-id')).rejects.toThrow('File not found');
        });

        it('should handle download failure', async () => {
            mockStorageManagerService.downloadFile.mockResolvedValue({
                success: false,
                error: 'Download failed',
            });

            await expect(service.getFileById('test-id')).rejects.toThrow('File stream not available');
        });
    });

    describe('File Listing', () => {
        it('should get all files with default pagination', async () => {
            const result = await service.getAllFiles();

            expect(result).toEqual({
                files: [mockFileMetadata],
                pagination: {
                    page: 1,
                    limit: 20,
                    total: 1,
                    totalPages: 1,
                    hasNext: false,
                    hasPrev: false,
                },
            });
            expect(mockFileMetadataService.getFilesByStorageProvider).toHaveBeenCalledWith(
                {
                    storageProvider: undefined,
                    category: undefined,
                },
                { page: 1, limit: 20 }
            );
        });

        it('should get files with custom pagination and filters', async () => {
            const options = {
                page: 2,
                limit: 10,
                storageProvider: 's3',
                category: 'document',
            };

            await service.getAllFiles(options);

            expect(mockFileMetadataService.getFilesByStorageProvider).toHaveBeenCalledWith(
                {
                    storageProvider: 's3',
                    category: 'document',
                },
                { page: 2, limit: 10 }
            );
        });
    });

    describe('File Deletion', () => {
        it('should delete file by ID successfully', async () => {
            const result = await service.deleteFile('test-id');

            expect(result).toEqual(mockFileMetadata);
            expect(mockFileMetadataService.getFileMetadataById).toHaveBeenCalledWith('test-id');
            expect(mockStorageManagerService.deleteFile).toHaveBeenCalledWith(
                'test-key',
                StorageProvider[StorageProvider.LOCAL]
            );
            expect(mockFileMetadataService.deleteFileMetadata).toHaveBeenCalledWith('test-id');
        });

        it('should handle metadata retrieval failure', async () => {
            mockFileMetadataService.getFileMetadataById.mockRejectedValue(new Error('File not found'));

            await expect(service.deleteFile('nonexistent-id')).rejects.toThrow('File not found');
        });

        it('should handle storage deletion failure', async () => {
            mockStorageManagerService.deleteFile.mockRejectedValue(new Error('Storage deletion failed'));

            await expect(service.deleteFile('test-id')).rejects.toThrow('Storage deletion failed');
        });

        it('should handle metadata deletion failure', async () => {
            mockFileMetadataService.deleteFileMetadata.mockRejectedValue(new Error('Metadata deletion failed'));

            await expect(service.deleteFile('test-id')).rejects.toThrow('Metadata deletion failed');
        });
    });

    describe('File Statistics', () => {
        it('should get file statistics', async () => {
            const mockStats = {
                totalCount: 100,
                totalSize: 50 * 1024 * 1024,
                byCategory: { document: 50, image: 30, video: 20 },
            };

            mockFileMetadataService.getFileStatistics.mockResolvedValue(mockStats);

            const result = await service.getFileStatistics();

            expect(result).toEqual({
                totalCount: 100,
                totalSize: 50 * 1024 * 1024,
                byStorageProvider: {},
                byCategory: { document: 50, image: 30, video: 20 },
            });
        });

        it('should handle statistics retrieval failure', async () => {
            mockFileMetadataService.getFileStatistics.mockRejectedValue(new Error('Stats failed'));

            await expect(service.getFileStatistics()).rejects.toThrow('Stats failed');
        });
    });

    describe('Error Handling', () => {
        it('should log errors during file upload', async () => {
            const loggerSpy = jest.spyOn(service['logger'], 'error');
            mockStorageManagerService.uploadFile.mockRejectedValue(new Error('Upload failed'));

            await expect(service.uploadFile(mockMulterFile)).rejects.toThrow();

            expect(loggerSpy).toHaveBeenCalledWith(
                'File upload failed: Upload failed',
                expect.any(Error)
            );
        });

        it('should log errors during file download', async () => {
            const loggerSpy = jest.spyOn(service['logger'], 'error');
            mockFileMetadataService.getFileMetadataById.mockRejectedValue(new Error('Download failed'));

            await expect(service.getFileById('test-id')).rejects.toThrow();

            expect(loggerSpy).toHaveBeenCalledWith(
                'Failed to get file test-id: Download failed',
                expect.any(Error)
            );
        });

        it('should log errors during file listing', async () => {
            const loggerSpy = jest.spyOn(service['logger'], 'error');
            mockFileMetadataService.getFilesByStorageProvider.mockRejectedValue(new Error('List failed'));

            await expect(service.getAllFiles()).rejects.toThrow();

            expect(loggerSpy).toHaveBeenCalledWith(
                'Failed to get all files: List failed',
                expect.any(Error)
            );
        });

        it('should log errors during file deletion', async () => {
            const loggerSpy = jest.spyOn(service['logger'], 'error');
            mockFileMetadataService.getFileMetadataById.mockRejectedValue(new Error('Delete failed'));

            await expect(service.deleteFile('test-id')).rejects.toThrow();

            expect(loggerSpy).toHaveBeenCalledWith(
                'Failed to delete file test-id: Delete failed',
                expect.any(Error)
            );
        });
    });

    describe('Integration Scenarios', () => {
        it('should handle complete upload-download cycle', async () => {
            // Upload
            const uploadResult = await service.uploadFile(mockMulterFile);
            expect(uploadResult.id).toBe('test-metadata-id');

            // Download
            const downloadResult = await service.getFileById('test-metadata-id');
            expect(downloadResult.metadata.id).toBe('test-metadata-id');

            // Verify calls
            expect(mockFileMetadataService.getFileMetadataById).toHaveBeenCalledWith('test-metadata-id');
            expect(mockStorageManagerService.downloadFile).toHaveBeenCalledWith(
                'test-key',
                StorageProvider[StorageProvider.LOCAL]
            );
        });

        it('should handle bulk operations with mixed results', async () => {
            const files = [
                mockMulterFile,
                { ...mockMulterFile, filename: 'fail.pdf' },
                { ...mockMulterFile, filename: 'success2.pdf' },
            ];

            mockFileValidationService.validateFiles.mockResolvedValue({
                valid: files,
                invalid: [],
            });

            mockStorageManagerService.uploadFile
                .mockResolvedValueOnce(mockUploadResult)
                .mockRejectedValueOnce(new Error('Upload 2 failed'))
                .mockResolvedValueOnce(mockUploadResult);

            const result = await service.uploadFiles(files);

            expect(result.files).toHaveLength(2);
            expect(result.failed).toHaveLength(1);
            expect(result.success).toBe(false);
        });
    });
});