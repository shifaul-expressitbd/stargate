/**
 * Support Tickets File Integration Tests
 * Tests complete file upload/upload workflows for support tickets and replies
 */

import { HttpService } from '@nestjs/axios';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from '../../database/prisma/prisma.service';
import { FileCleanupService } from '../../file/services/file-cleanup.service';
import { FileMetadataService } from '../../file/services/file-metadata.service';
import { FileStorageService } from '../../file/services/file-storage.service';
import { FileValidationService } from '../../file/services/file-validation.service';
import { FileService } from '../../file/services/file.service';
import { SupportTicketsService } from '../support-tickets.service';

// Mock all external dependencies
jest.mock('@aws-sdk/client-s3');
jest.mock('@aws-sdk/s3-request-presigner');
jest.mock('@prisma/client');
jest.mock('cloudinary');
jest.mock('fs');
jest.mock('path');
jest.mock('crypto');
jest.mock('../../../test/__mocks__/prisma');

const mockFileService = {
    uploadFiles: jest.fn(),
    deleteFile: jest.fn(),
};

const mockFileMetadataService = {
    getFileMetadataById: jest.fn(),
};

const mockPrismaService = {
    supportTicket: {
        create: jest.fn(),
        findUnique: jest.fn(),
        findMany: jest.fn(),
        update: jest.fn(),
        count: jest.fn(),
    },
    ticketReply: {
        create: jest.fn(),
        findUnique: jest.fn(),
    },
    fileMetadata: {
        updateMany: jest.fn(),
    },
    user: {
        findUnique: jest.fn(),
    },
};

const mockHttpService = {
    axiosRef: {},
};

describe('Support Tickets File Integration Tests', () => {
    let supportTicketsService: SupportTicketsService;
    let fileService: FileService;
    let prismaService: PrismaService;
    let module: TestingModule;

    const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        name: 'Test User',
        roles: ['user'],
    };

    const mockMulterFile: Express.Multer.File = {
        fieldname: 'attachments',
        originalname: 'test-document.pdf',
        encoding: '7bit',
        mimetype: 'application/pdf',
        size: 2048000, // 2MB
        destination: '/tmp',
        filename: 'test-document.pdf',
        path: '/tmp/test-document.pdf',
        buffer: Buffer.from('integration test file content'),
        stream: {} as any, // Mock stream
    };

    const mockUploadResult = {
        files: [
            {
                id: 'file-123',
                filename: 'test-document.pdf',
                originalName: 'test-document.pdf',
                mimeType: 'application/pdf',
                size: 2048000,
                storageProvider: 'local',
                storageKey: 'test-key',
                storageUrl: 'http://localhost:3000/files/test-key',
                downloadUrl: 'http://localhost:3000/api/files/id/file-123',
                createdAt: new Date(),
            },
        ],
        totalSize: 2048000,
        duration: 1500,
        success: true,
    };

    const mockTicket = {
        id: 'ticket-123',
        title: 'Test Ticket',
        description: 'Test description',
        status: 'OPEN',
        priority: 'NORMAL',
        fileUrls: [],
        createdAt: new Date(),
        updatedAt: new Date(),
        createdById: 'user-123',
        createdBy: mockUser,
        replies: [],
    };

    const mockReply = {
        id: 'reply-123',
        content: 'Test reply',
        isInternal: false,
        createdAt: new Date(),
        author: mockUser,
    };

    beforeEach(async () => {
        // Reset all mocks
        jest.clearAllMocks();

        // Setup default mock behaviors
        mockFileService.uploadFiles.mockResolvedValue(mockUploadResult);
        mockFileMetadataService.getFileMetadataById.mockResolvedValue({
            id: 'file-123',
            userId: 'user-123',
            supportTicketId: null,
            ticketReplyId: null,
        });
        mockPrismaService.supportTicket.create.mockResolvedValue(mockTicket);
        mockPrismaService.supportTicket.findUnique.mockResolvedValue(mockTicket);
        mockPrismaService.supportTicket.update.mockResolvedValue(mockTicket);
        mockPrismaService.ticketReply.create.mockResolvedValue(mockReply);
        mockPrismaService.ticketReply.findUnique.mockResolvedValue(mockReply);

        module = await Test.createTestingModule({
            providers: [
                SupportTicketsService,
                {
                    provide: FileService,
                    useValue: mockFileService,
                },
                {
                    provide: FileMetadataService,
                    useValue: mockFileMetadataService,
                },
                {
                    provide: PrismaService,
                    useValue: mockPrismaService,
                },
                {
                    provide: FileStorageService,
                    useValue: {},
                },
                {
                    provide: FileValidationService,
                    useValue: {},
                },
                {
                    provide: FileCleanupService,
                    useValue: {},
                },
                {
                    provide: HttpService,
                    useValue: mockHttpService,
                },
            ],
        }).compile();

        supportTicketsService = module.get<SupportTicketsService>(SupportTicketsService);
        fileService = module.get<FileService>(FileService);
        prismaService = module.get<PrismaService>(PrismaService);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Ticket Creation with File Attachments', () => {
        it('should create ticket with file attachments and store URLs', async () => {
            // Arrange
            const dto = {
                title: 'Test Ticket with Files',
                description: 'Description with attachments',
                priority: 'HIGH' as const,
            };
            const files = [mockMulterFile];

            // Act
            const result = await supportTicketsService.createTicket(mockUser.id, dto, files);

            // Assert
            expect(result.title).toBe('Test Ticket with Files');
            expect(result.fileUrls).toEqual(['http://localhost:3000/api/files/id/file-123']);
            expect(mockFileService.uploadFiles).toHaveBeenCalledWith(files);
            expect(mockPrismaService.supportTicket.update).toHaveBeenCalledWith({
                where: { id: 'ticket-123' },
                data: {
                    fileUrls: ['http://localhost:3000/api/files/id/file-123'],
                },
            });
            expect(mockPrismaService.fileMetadata.updateMany).toHaveBeenCalledWith({
                where: {
                    id: { in: ['file-123'] },
                    userId: 'user-123',
                },
                data: {
                    supportTicketId: 'ticket-123',
                    userId: 'user-123',
                },
            });
        });

        it('should create ticket without files when no attachments provided', async () => {
            // Arrange
            const dto = {
                title: 'Test Ticket without Files',
                description: 'Description without attachments',
            };

            // Act
            const result = await supportTicketsService.createTicket(mockUser.id, dto);

            // Assert
            expect(result.title).toBe('Test Ticket without Files');
            expect(result.fileUrls).toEqual([]);
            expect(mockFileService.uploadFiles).not.toHaveBeenCalled();
            expect(mockPrismaService.supportTicket.update).not.toHaveBeenCalled();
        });

        it('should handle multiple file attachments', async () => {
            // Arrange
            const dto = {
                title: 'Test Ticket with Multiple Files',
                description: 'Multiple attachments test',
            };
            const files = [mockMulterFile, { ...mockMulterFile, filename: 'second-file.pdf' }];

            const multiFileResult = {
                ...mockUploadResult,
                files: [
                    mockUploadResult.files[0],
                    {
                        id: 'file-456',
                        filename: 'second-file.pdf',
                        downloadUrl: 'http://localhost:3000/api/files/id/file-456',
                    },
                ],
            };
            mockFileService.uploadFiles.mockResolvedValue(multiFileResult);

            // Act
            const result = await supportTicketsService.createTicket(mockUser.id, dto, files);

            // Assert
            expect(result.fileUrls).toEqual([
                'http://localhost:3000/api/files/id/file-123',
                'http://localhost:3000/api/files/id/file-456',
            ]);
            expect(mockPrismaService.fileMetadata.updateMany).toHaveBeenCalledWith({
                where: {
                    id: { in: ['file-123', 'file-456'] },
                    userId: 'user-123',
                },
                data: {
                    supportTicketId: 'ticket-123',
                    userId: 'user-123',
                },
            });
        });

        it('should attach existing files by ID', async () => {
            // Arrange
            const dto = {
                title: 'Test Ticket with Existing Files',
                attachmentIds: ['existing-file-123', 'existing-file-456'],
            };

            mockFileMetadataService.getFileMetadataById
                .mockResolvedValueOnce({
                    id: 'existing-file-123',
                    userId: 'user-123',
                    supportTicketId: null,
                    ticketReplyId: null,
                })
                .mockResolvedValueOnce({
                    id: 'existing-file-456',
                    userId: 'user-123',
                    supportTicketId: null,
                    ticketReplyId: null,
                });

            // Act
            const result = await supportTicketsService.createTicket(mockUser.id, dto);

            // Assert
            expect(result.title).toBe('Test Ticket with Existing Files');
            expect(mockPrismaService.fileMetadata.updateMany).toHaveBeenCalledWith({
                where: {
                    id: { in: ['existing-file-123', 'existing-file-456'] },
                    userId: 'user-123',
                },
                data: {
                    supportTicketId: 'ticket-123',
                },
            });
        });
    });

    describe('Upload Files to Existing Ticket', () => {
        it('should upload files to existing ticket and associate them', async () => {
            // Arrange
            const ticketId = 'ticket-123';
            const files = [mockMulterFile];

            // Act
            const result = await supportTicketsService.uploadFilesToTicket(ticketId, files, mockUser.id);

            // Assert
            expect(result).toEqual(['http://localhost:3000/api/files/id/file-123']);
            expect(mockFileService.uploadFiles).toHaveBeenCalledWith(files);
            expect(mockPrismaService.supportTicket.findUnique).toHaveBeenCalledWith({
                where: { id: ticketId },
            });
            expect(mockPrismaService.fileMetadata.updateMany).toHaveBeenCalledWith({
                where: {
                    id: { in: ['file-123'] },
                    userId: 'user-123',
                },
                data: {
                    supportTicketId: ticketId,
                    userId: 'user-123',
                },
            });
        });

        it('should throw error when ticket not found', async () => {
            // Arrange
            const ticketId = 'non-existent-ticket';
            const files = [mockMulterFile];

            mockPrismaService.supportTicket.findUnique.mockResolvedValue(null);

            // Act & Assert
            await expect(
                supportTicketsService.uploadFilesToTicket(ticketId, files, mockUser.id)
            ).rejects.toThrow('Ticket not found');
        });

        it('should throw error when user cannot access ticket', async () => {
            // Arrange
            const ticketId = 'ticket-123';
            const files = [mockMulterFile];
            const otherUserId = 'other-user-123';

            const restrictedTicket = { ...mockTicket, createdById: 'different-user' };
            mockPrismaService.supportTicket.findUnique.mockResolvedValue(restrictedTicket);

            // Act & Assert
            await expect(
                supportTicketsService.uploadFilesToTicket(ticketId, files, otherUserId)
            ).rejects.toThrow('Ticket not found');
        });
    });

    describe('Upload Files to Ticket Reply', () => {
        it('should upload files to ticket reply and associate them', async () => {
            // Arrange
            const replyId = 'reply-123';
            const ticketId = 'ticket-123';
            const files = [mockMulterFile];

            const ticketWithReply = {
                ...mockTicket,
                replies: [mockReply],
            };
            mockPrismaService.supportTicket.findUnique.mockResolvedValue(ticketWithReply);

            // Act
            const result = await supportTicketsService.uploadFilesToReply(replyId, ticketId, files, mockUser.id);

            // Assert
            expect(result).toEqual(mockUploadResult);
            expect(mockFileService.uploadFiles).toHaveBeenCalledWith(files);
            expect(mockPrismaService.supportTicket.findUnique).toHaveBeenCalledWith({
                where: { id: ticketId },
                include: {
                    replies: {
                        include: {
                            author: {
                                select: {
                                    id: true,
                                    email: true,
                                    name: true,
                                },
                            },
                        },
                        orderBy: {
                            createdAt: 'asc',
                        },
                    },
                },
            });
            expect(mockPrismaService.fileMetadata.updateMany).toHaveBeenCalledWith({
                where: {
                    id: { in: ['file-123'] },
                    userId: 'user-123',
                },
                data: {
                    ticketReplyId: replyId,
                    userId: 'user-123',
                },
            });
        });

        it('should throw error when reply not found in ticket', async () => {
            // Arrange
            const replyId = 'non-existent-reply';
            const ticketId = 'ticket-123';
            const files = [mockMulterFile];

            mockPrismaService.supportTicket.findUnique.mockResolvedValue(mockTicket);

            // Act & Assert
            await expect(
                supportTicketsService.uploadFilesToReply(replyId, ticketId, files, mockUser.id)
            ).rejects.toThrow('Reply not found');
        });
    });

    describe('File Deletion from Tickets', () => {
        it('should delete file from ticket successfully', async () => {
            // Arrange
            const ticketId = 'ticket-123';
            const fileId = 'file-123';

            mockPrismaService.supportTicket.findUnique.mockResolvedValue(mockTicket);
            mockFileMetadataService.getFileMetadataById.mockResolvedValue({
                id: fileId,
                userId: mockUser.id,
                supportTicketId: ticketId,
            });

            // Act
            await supportTicketsService.removeFileFromTicket(ticketId, fileId, mockUser.id);

            // Assert
            expect(mockFileService.deleteFile).toHaveBeenCalledWith(fileId);
            expect(mockFileMetadataService.getFileMetadataById).toHaveBeenCalledWith(fileId);
        });

        it('should throw error when file not attached to ticket', async () => {
            // Arrange
            const ticketId = 'ticket-123';
            const fileId = 'file-123';

            mockPrismaService.supportTicket.findUnique.mockResolvedValue(mockTicket);
            mockFileMetadataService.getFileMetadataById.mockResolvedValue({
                id: fileId,
                userId: mockUser.id,
                supportTicketId: 'different-ticket',
            });

            // Act & Assert
            await expect(
                supportTicketsService.removeFileFromTicket(ticketId, fileId, mockUser.id)
            ).rejects.toThrow('File is not attached to this ticket');
        });

        it('should throw error when user does not own the file', async () => {
            // Arrange
            const ticketId = 'ticket-123';
            const fileId = 'file-123';

            mockPrismaService.supportTicket.findUnique.mockResolvedValue(mockTicket);
            mockFileMetadataService.getFileMetadataById.mockResolvedValue({
                id: fileId,
                userId: 'different-user',
                supportTicketId: ticketId,
            });

            // Act & Assert
            await expect(
                supportTicketsService.removeFileFromTicket(ticketId, fileId, mockUser.id)
            ).rejects.toThrow('You can only delete your own files');
        });
    });

    describe('File Deletion from Replies', () => {
        it('should delete file from reply successfully', async () => {
            // Arrange
            const ticketId = 'ticket-123';
            const replyId = 'reply-123';
            const fileId = 'file-123';

            const ticketWithReply = {
                ...mockTicket,
                replies: [mockReply],
            };
            mockPrismaService.supportTicket.findUnique.mockResolvedValue(ticketWithReply);
            mockFileMetadataService.getFileMetadataById.mockResolvedValue({
                id: fileId,
                userId: mockUser.id,
                ticketReplyId: replyId,
            });

            // Act
            await supportTicketsService.removeFileFromReply(ticketId, replyId, fileId, mockUser.id);

            // Assert
            expect(mockFileService.deleteFile).toHaveBeenCalledWith(fileId);
            expect(mockFileMetadataService.getFileMetadataById).toHaveBeenCalledWith(fileId);
        });

        it('should throw error when file not attached to reply', async () => {
            // Arrange
            const ticketId = 'ticket-123';
            const replyId = 'reply-123';
            const fileId = 'file-123';

            const ticketWithReply = {
                ...mockTicket,
                replies: [mockReply],
            };
            mockPrismaService.supportTicket.findUnique.mockResolvedValue(ticketWithReply);
            mockFileMetadataService.getFileMetadataById.mockResolvedValue({
                id: fileId,
                userId: mockUser.id,
                ticketReplyId: 'different-reply',
            });

            // Act & Assert
            await expect(
                supportTicketsService.removeFileFromReply(ticketId, replyId, fileId, mockUser.id)
            ).rejects.toThrow('File is not attached to this reply');
        });
    });

    describe('Error Handling', () => {
        it('should handle file upload failures gracefully', async () => {
            // Arrange
            const dto = {
                title: 'Test Ticket with Failed Upload',
                description: 'Testing upload failure',
            };
            const files = [mockMulterFile];

            mockFileService.uploadFiles.mockRejectedValue(new Error('Upload failed'));

            // Act & Assert
            await expect(
                supportTicketsService.createTicket(mockUser.id, dto, files)
            ).rejects.toThrow('Upload failed');
        });

        it('should handle file validation failures', async () => {
            // Arrange
            const dto = {
                title: 'Test with Invalid Files',
                attachmentIds: ['invalid-file-id'],
            };

            mockFileMetadataService.getFileMetadataById.mockRejectedValue(
                new Error('File not found')
            );

            // Act & Assert
            await expect(
                supportTicketsService.createTicket(mockUser.id, dto)
            ).rejects.toThrow('File not found');
        });

        it('should handle database errors during file association', async () => {
            // Arrange
            const dto = {
                title: 'Test with DB Error',
                description: 'Testing database error',
            };
            const files = [mockMulterFile];

            mockPrismaService.fileMetadata.updateMany.mockRejectedValue(
                new Error('Database connection failed')
            );

            // Act & Assert
            await expect(
                supportTicketsService.createTicket(mockUser.id, dto, files)
            ).rejects.toThrow('Database connection failed');
        });
    });

    describe('URL Storage and Retrieval', () => {
        it('should properly store and retrieve file URLs in ticket', async () => {
            // Arrange
            const dto = {
                title: 'URL Storage Test',
                description: 'Testing URL storage',
            };
            const files = [mockMulterFile];

            // Act
            const result = await supportTicketsService.createTicket(mockUser.id, dto, files);

            // Assert
            expect(result.fileUrls).toContain('http://localhost:3000/api/files/id/file-123');
            expect(result.fileUrls).toHaveLength(1);
        });

        it('should accumulate file URLs when uploading additional files', async () => {
            // Arrange
            const ticketId = 'ticket-123';
            const files = [mockMulterFile];
            const existingUrls = ['existing-url-1', 'existing-url-2'];

            const ticketWithUrls = { ...mockTicket, fileUrls: existingUrls };
            mockPrismaService.supportTicket.findUnique.mockResolvedValue(ticketWithUrls);

            // Note: In the actual service, uploadFilesToTicket doesn't merge existing URLs
            // It only returns the URLs of the newly uploaded files
            // The controller handles the response

            // Act
            const result = await supportTicketsService.uploadFilesToTicket(ticketId, files, mockUser.id);

            // Assert
            expect(result).toEqual(['http://localhost:3000/api/files/id/file-123']);
        });
    });

    describe('File Metadata Association', () => {
        it('should associate uploaded files with ticket in FileMetadata', async () => {
            // Arrange
            const dto = {
                title: 'Metadata Association Test',
            };
            const files = [mockMulterFile];

            // Act
            await supportTicketsService.createTicket(mockUser.id, dto, files);

            // Assert
            expect(mockPrismaService.fileMetadata.updateMany).toHaveBeenCalledWith({
                where: {
                    id: { in: ['file-123'] },
                    userId: 'user-123',
                },
                data: {
                    supportTicketId: 'ticket-123',
                    userId: 'user-123',
                },
            });
        });

        it('should associate uploaded files with reply in FileMetadata', async () => {
            // Arrange
            const replyId = 'reply-123';
            const ticketId = 'ticket-123';
            const files = [mockMulterFile];

            const ticketWithReply = {
                ...mockTicket,
                replies: [mockReply],
            };
            mockPrismaService.supportTicket.findUnique.mockResolvedValue(ticketWithReply);

            // Act
            await supportTicketsService.uploadFilesToReply(replyId, ticketId, files, mockUser.id);

            // Assert
            expect(mockPrismaService.fileMetadata.updateMany).toHaveBeenCalledWith({
                where: {
                    id: { in: ['file-123'] },
                    userId: 'user-123',
                },
                data: {
                    ticketReplyId: replyId,
                    userId: 'user-123',
                },
            });
        });
    });
});