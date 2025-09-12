/**
 * File Metadata Service Tests
 * Tests the file metadata service that manages file metadata in the database
 */

import { BadRequestException, NotFoundException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from '../../../database/prisma/prisma.service';
import { FileCategory, FileSearchCriteria } from '../../interfaces/file-metadata.interface';
import { FileMetadataService } from '../file-metadata.service';

// Mock PrismaService
const mockPrismaService = {
    fileMetadata: {
        create: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
        findMany: jest.fn(),
        count: jest.fn(),
        aggregate: jest.fn(),
    },
};

describe('FileMetadataService', () => {
    let service: FileMetadataService;
    let prismaService: PrismaService;

    const mockPrismaFileMetadata = {
        id: 'test-file-id',
        filename: 'test-document.pdf',
        originalName: 'original-test-document.pdf',
        mimeType: 'application/pdf',
        size: 1024000,
        path: 'uploads/test-document.pdf',
        storageProvider: 'local',
        storageKey: 'test-document-key',
        storageUrl: 'http://localhost:3000/files/test-document.pdf',
        category: 'document',
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    const mockExtendedFileMetadata = {
        ...mockPrismaFileMetadata,
        extension: 'pdf',
        formattedSize: '1 MB',
        isImage: false,
        isDocument: true,
        downloadUrl: '/api/files/test-file-id',
    };

    beforeEach(async () => {
        // Reset all mocks
        jest.clearAllMocks();

        // Setup mock implementations
        mockPrismaService.fileMetadata.create.mockResolvedValue(mockPrismaFileMetadata);
        mockPrismaService.fileMetadata.findUnique.mockResolvedValue(mockPrismaFileMetadata);
        mockPrismaService.fileMetadata.update.mockResolvedValue(mockPrismaFileMetadata);
        mockPrismaService.fileMetadata.delete.mockResolvedValue(mockPrismaFileMetadata);
        mockPrismaService.fileMetadata.findMany.mockResolvedValue([mockPrismaFileMetadata]);
        mockPrismaService.fileMetadata.count.mockResolvedValue(1);
        mockPrismaService.fileMetadata.aggregate.mockResolvedValue({
            _count: { id: 1 },
            _sum: { size: 1024000 },
        });

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                FileMetadataService,
                {
                    provide: PrismaService,
                    useValue: mockPrismaService,
                },
            ],
        }).compile();

        service = module.get<FileMetadataService>(FileMetadataService);
        prismaService = module.get<PrismaService>(PrismaService);
    });

    describe('Initialization', () => {
        it('should be defined', () => {
            expect(service).toBeDefined();
        });
    });

    describe('Create File Metadata', () => {
        const createData = {
            filename: 'test-document.pdf',
            originalName: 'original-test-document.pdf',
            mimeType: 'application/pdf',
            size: 1024000,
            storageProvider: 'local',
            storageKey: 'test-document-key',
            storageUrl: 'http://localhost:3000/files/test-document.pdf',
            category: 'document',
        };

        it('should create file metadata successfully', async () => {
            const result = await service.createFileMetadata(createData);

            expect(result).toEqual(mockExtendedFileMetadata);
            expect(mockPrismaService.fileMetadata.create).toHaveBeenCalledWith({
                data: {
                    filename: 'test-document.pdf',
                    originalName: 'original-test-document.pdf',
                    mimeType: 'application/pdf',
                    size: 1024000,
                    path: 'test-document-key',
                    storageProvider: 'local',
                    storageKey: 'test-document-key',
                    storageUrl: 'http://localhost:3000/files/test-document.pdf',
                    category: 'document',
                },
            });
        });

        it('should handle database errors during creation', async () => {
            mockPrismaService.fileMetadata.create.mockRejectedValue(new Error('Database error'));

            await expect(service.createFileMetadata(createData)).rejects.toThrow(BadRequestException);
            expect(mockPrismaService.fileMetadata.create).toHaveBeenCalled();
        });
    });

    describe('Get File Metadata by ID', () => {
        it('should get file metadata by ID successfully', async () => {
            const result = await service.getFileMetadataById('test-file-id');

            expect(result).toEqual(mockExtendedFileMetadata);
            expect(mockPrismaService.fileMetadata.findUnique).toHaveBeenCalledWith({
                where: { id: 'test-file-id' },
            });
        });

        it('should throw NotFoundException for nonexistent file', async () => {
            mockPrismaService.fileMetadata.findUnique.mockResolvedValue(null);

            await expect(service.getFileMetadataById('nonexistent-id')).rejects.toThrow(NotFoundException);
        });

        it('should handle database errors during retrieval', async () => {
            mockPrismaService.fileMetadata.findUnique.mockRejectedValue(new Error('Database error'));

            await expect(service.getFileMetadataById('test-file-id')).rejects.toThrow(BadRequestException);
        });
    });

    describe('Update File Metadata', () => {
        const updateData = {
            originalName: 'updated-name.pdf',
            category: 'document' as FileCategory,
        };

        it('should update file metadata successfully', async () => {
            const result = await service.updateFileMetadata('test-file-id', updateData);

            expect(result).toEqual(mockExtendedFileMetadata);
            expect(mockPrismaService.fileMetadata.update).toHaveBeenCalledWith({
                where: { id: 'test-file-id' },
                data: {
                    originalName: 'updated-name.pdf',
                    category: 'document',
                },
            });
        });

        it('should handle partial updates', async () => {
            const partialUpdate = { originalName: 'new-name.pdf' };

            await service.updateFileMetadata('test-file-id', partialUpdate);

            expect(mockPrismaService.fileMetadata.update).toHaveBeenCalledWith({
                where: { id: 'test-file-id' },
                data: {
                    originalName: 'new-name.pdf',
                },
            });
        });

        it('should handle database errors during update', async () => {
            mockPrismaService.fileMetadata.update.mockRejectedValue(new Error('Database error'));

            await expect(service.updateFileMetadata('test-file-id', updateData)).rejects.toThrow(BadRequestException);
        });
    });

    describe('Delete File Metadata', () => {
        it('should delete file metadata successfully', async () => {
            const result = await service.deleteFileMetadata('test-file-id');

            expect(result).toEqual(mockExtendedFileMetadata);
            expect(mockPrismaService.fileMetadata.findUnique).toHaveBeenCalledWith({
                where: { id: 'test-file-id' },
            });
            expect(mockPrismaService.fileMetadata.delete).toHaveBeenCalledWith({
                where: { id: 'test-file-id' },
            });
        });

        it('should handle database errors during deletion', async () => {
            mockPrismaService.fileMetadata.delete.mockRejectedValue(new Error('Database error'));

            await expect(service.deleteFileMetadata('test-file-id')).rejects.toThrow(BadRequestException);
        });
    });

    describe('Search Files', () => {
        const searchCriteria: FileSearchCriteria = {
            query: 'test document',
            category: FileCategory.DOCUMENT,
            mimeType: 'application/pdf',
            uploaderId: 'user-123',
            sizeRange: { min: 1000, max: 5000000 },
            dateRange: { from: new Date('2024-01-01'), to: new Date('2024-12-31') },
        };

        const pagination = { page: 1, limit: 20 };

        it('should search files successfully', async () => {
            const result = await service.searchFiles(searchCriteria, pagination);

            expect(result).toEqual({
                files: [mockExtendedFileMetadata],
                total: 1,
                page: 1,
                limit: 20,
                totalPages: 1,
            });
            expect(mockPrismaService.fileMetadata.findMany).toHaveBeenCalledWith({
                where: expect.objectContaining({
                    OR: [
                        { filename: { contains: 'test document', mode: 'insensitive' } },
                        { originalName: { contains: 'test document', mode: 'insensitive' } },
                    ],
                    uploadedById: 'user-123',
                    mimeType: 'application/pdf',
                    size: { gte: 1000, lte: 5000000 },
                    createdAt: {
                        gte: new Date('2024-01-01'),
                        lte: new Date('2024-12-31'),
                    },
                }),
                skip: 0,
                take: 20,
                orderBy: { createdAt: 'desc' },
            });
        });

        it('should handle empty search criteria', async () => {
            const result = await service.searchFiles({}, pagination);

            expect(result.files).toHaveLength(1);
            expect(mockPrismaService.fileMetadata.findMany).toHaveBeenCalledWith({
                where: {},
                skip: 0,
                take: 20,
                orderBy: { createdAt: 'desc' },
            });
        });

        it('should handle size range filters', async () => {
            const criteriaWithSize = {
                sizeRange: { min: 1000 },
            };

            await service.searchFiles(criteriaWithSize, pagination);

            expect(mockPrismaService.fileMetadata.findMany).toHaveBeenCalledWith({
                where: { size: { gte: 1000 } },
                skip: 0,
                take: 20,
                orderBy: { createdAt: 'desc' },
            });
        });

        it('should handle related entity filters', async () => {
            const criteriaWithRelations = {
                relatedTo: {
                    ticketId: 'ticket-123',
                    replyId: 'reply-456',
                },
            };

            await service.searchFiles(criteriaWithRelations, pagination);

            expect(mockPrismaService.fileMetadata.findMany).toHaveBeenCalledWith({
                where: {
                    relatedTicketId: 'ticket-123',
                    relatedReplyId: 'reply-456',
                },
                skip: 0,
                take: 20,
                orderBy: { createdAt: 'desc' },
            });
        });

        it('should handle database errors during search', async () => {
            mockPrismaService.fileMetadata.findMany.mockRejectedValue(new Error('Database error'));

            await expect(service.searchFiles(searchCriteria, pagination)).rejects.toThrow(BadRequestException);
        });
    });

    describe('Get Files by User ID', () => {
        it('should get files by user ID', async () => {
            const result = await service.getFilesByUserId('user-123');

            expect(result.files).toHaveLength(1);
            expect(mockPrismaService.fileMetadata.findMany).toHaveBeenCalledWith({
                where: { uploadedById: 'user-123' },
                skip: 0,
                take: 20,
                orderBy: { createdAt: 'desc' },
            });
        });
    });

    describe('Get File Statistics', () => {
        it('should get file statistics', async () => {
            const result = await service.getFileStatistics();

            expect(result).toEqual({
                totalCount: 1,
                totalSize: 1024000,
                byCategory: {},
                byUser: [],
            });
            expect(mockPrismaService.fileMetadata.aggregate).toHaveBeenCalledWith({
                _count: { id: true },
                _sum: { size: true },
            });
        });

        it('should handle database errors during statistics', async () => {
            mockPrismaService.fileMetadata.aggregate.mockRejectedValue(new Error('Database error'));

            await expect(service.getFileStatistics()).rejects.toThrow(BadRequestException);
        });
    });

    describe('Get Files by Storage Provider', () => {
        it('should get files by storage provider', async () => {
            const result = await service.getFilesByStorageProvider(
                { storageProvider: 's3', category: 'document' },
                { page: 1, limit: 10 }
            );

            expect(result).toEqual({
                files: [mockExtendedFileMetadata],
                total: 1,
                page: 1,
                limit: 10,
                totalPages: 1,
            });
            expect(mockPrismaService.fileMetadata.findMany).toHaveBeenCalledWith({
                where: {
                    storageProvider: 's3',
                    category: 'document',
                },
                skip: 0,
                take: 10,
                orderBy: { createdAt: 'desc' },
            });
        });

        it('should handle empty filters', async () => {
            await service.getFilesByStorageProvider({}, { page: 1, limit: 20 });

            expect(mockPrismaService.fileMetadata.findMany).toHaveBeenCalledWith({
                where: {},
                skip: 0,
                take: 20,
                orderBy: { createdAt: 'desc' },
            });
        });
    });

    describe('Extend File Metadata', () => {
        it('should extend basic metadata with computed properties', async () => {
            const extended = await service['extendFileMetadata'](mockPrismaFileMetadata);

            expect(extended).toEqual({
                ...mockPrismaFileMetadata,
                extension: 'pdf',
                formattedSize: expect.any(String),
                category: FileCategory.DOCUMENT,
                isImage: false,
                isDocument: true,
                canPreview: true,
                downloadUrl: '/api/files/test-file-id',
            });
        });

        it('should handle image files', async () => {
            const imageFile = { ...mockPrismaFileMetadata, mimeType: 'image/jpeg' };
            const extended = await service['extendFileMetadata'](imageFile);

            expect(extended.category).toBe(FileCategory.IMAGE);
            expect(extended.isImage).toBe(true);
            expect(extended.isDocument).toBe(false);
        });

        it('should handle video files', async () => {
            const videoFile = { ...mockPrismaFileMetadata, mimeType: 'video/mp4' };
            const extended = await service['extendFileMetadata'](videoFile);

            expect(extended.category).toBe(FileCategory.VIDEO);
        });

        it('should handle archive files', async () => {
            const archiveFile = { ...mockPrismaFileMetadata, mimeType: 'application/zip' };
            const extended = await service['extendFileMetadata'](archiveFile);

            expect(extended.category).toBe(FileCategory.ARCHIVE);
        });
    });

    describe('Format File Size', () => {
        it('should format bytes correctly', () => {
            expect(service['formatFileSize'](1024)).toBe('1.0 KB');
            expect(service['formatFileSize'](1024 * 1024)).toBe('1.0 MB');
            expect(service['formatFileSize'](1024 * 1024 * 1024)).toBe('1.0 GB');
        });
    });

    describe('Integration Scenarios', () => {
        it('should handle complete CRUD cycle', async () => {
            // Create
            const created = await service.createFileMetadata({
                filename: 'test.pdf',
                originalName: 'test.pdf',
                mimeType: 'application/pdf',
                size: 1024,
                storageProvider: 'local',
                storageKey: 'test-key',
            });
            expect(created.id).toBe('test-file-id');

            // Read
            const retrieved = await service.getFileMetadataById('test-file-id');
            expect(retrieved.id).toBe('test-file-id');

            // Update
            const updated = await service.updateFileMetadata('test-file-id', {
                originalName: 'updated.pdf',
            });
            expect(updated.originalName).toBe('original-test-document.pdf'); // Mock returns same data

            // Delete
            const deleted = await service.deleteFileMetadata('test-file-id');
            expect(deleted.id).toBe('test-file-id');
        });

        it('should handle search and pagination', async () => {
            mockPrismaService.fileMetadata.count.mockResolvedValue(25);
            mockPrismaService.fileMetadata.findMany.mockResolvedValue(
                Array(10).fill(mockPrismaFileMetadata)
            );

            const result = await service.searchFiles({}, { page: 2, limit: 10 });

            expect(result.page).toBe(2);
            expect(result.limit).toBe(10);
            expect(result.total).toBe(25);
            expect(result.totalPages).toBe(3);
            expect(result.files).toHaveLength(10);

            expect(mockPrismaService.fileMetadata.findMany).toHaveBeenCalledWith({
                where: {},
                skip: 10,
                take: 10,
                orderBy: { createdAt: 'desc' },
            });
        });
    });
});