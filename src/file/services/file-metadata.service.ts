/**
 * File metadata service for managing file metadata in the database
 * Handles CRUD operations for file metadata using Prisma
 * Focuses on storage provider metadata management without complex relations
 */

import {
    BadRequestException,
    Inject,
    Injectable,
    Logger,
    NotFoundException,
} from '@nestjs/common';
import { FileMetadata as PrismaFileMetadata } from '@prisma/client';
import * as crypto from 'crypto';
import { PrismaService } from '../../database/prisma/prisma.service';
import { ExtendedFileMetadata, FileSearchCriteria } from '../interfaces/file-metadata.interface';
import { StorageProvider } from '../interfaces/storage.interface';

/**
 * File metadata service
 * Manages file metadata operations in the database
 */
@Injectable()
export class FileMetadataService {
    private readonly logger = new Logger(FileMetadataService.name);

    constructor(
        @Inject(PrismaService) private prisma: PrismaService,
    ) { }

    /**
     * Create file metadata record
     * @param data - File metadata data
     * @returns Created file metadata
     */
    async createFileMetadata(data: {
        filename: string;
        originalName: string;
        mimeType: string;
        size: number;
        storageProvider: string;
        storageKey?: string;
        storageUrl?: string;
        category?: string;
    }): Promise<ExtendedFileMetadata> {
        try {
            // Comprehensive validation and logging
            this.logger.log(`Creating file metadata for: ${data.filename}`, {
                originalName: data.originalName,
                mimeType: data.mimeType,
                size: data.size,
                storageProvider: data.storageProvider,
                hasStorageKey: !!data.storageKey,
                storageKey: data.storageKey,
                storageUrl: data.storageUrl,
                category: data.category,
            });

            // Validate required fields
            if (!data.filename || data.filename.trim() === '') {
                const errorMsg = 'Filename is required and cannot be empty';
                this.logger.error(errorMsg, { filename: data.filename });
                throw new BadRequestException(errorMsg);
            }

            if (!data.originalName || data.originalName.trim() === '') {
                const errorMsg = 'Original name is required and cannot be empty';
                this.logger.error(errorMsg, { originalName: data.originalName });
                throw new BadRequestException(errorMsg);
            }

            if (!data.storageProvider || data.storageProvider.trim() === '') {
                const errorMsg = 'Storage provider is required and cannot be empty';
                this.logger.error(errorMsg, { storageProvider: data.storageProvider });
                throw new BadRequestException(errorMsg);
            }

            // Handle storageKey validation and placeholder assignment
            let finalStorageKey = data.storageKey;
            let storageUrl = data.storageUrl;

            if (!data.storageKey || data.storageKey.trim() === '') {
                // Generate a placeholder storage key for failed uploads
                const placeholderKey = `failed-upload-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
                finalStorageKey = placeholderKey;
                storageUrl = undefined; // Clear storage URL for failed uploads

                this.logger.warn(`Storage key was empty or invalid, using placeholder: ${placeholderKey}`, {
                    originalStorageKey: data.storageKey,
                    filename: data.filename,
                    originalName: data.originalName,
                });
            }

            // Ensure finalStorageKey is defined at this point
            if (!finalStorageKey) {
                const errorMsg = 'Storage key is required';
                this.logger.error(errorMsg, { data });
                throw new BadRequestException(errorMsg);
            }

            // Validate storageKey format if present
            if (finalStorageKey.length > 1000) {
                const errorMsg = 'Storage key is too long (max 1000 characters)';
                this.logger.error(errorMsg, {
                    storageKey: finalStorageKey,
                    length: finalStorageKey.length
                });
                throw new BadRequestException(errorMsg);
            }

            // Validate MIME type format
            if (!data.mimeType || !data.mimeType.includes('/')) {
                this.logger.warn(`Invalid MIME type format: ${data.mimeType}, setting to default`, {
                    filename: data.filename,
                    originalMimeType: data.mimeType
                });
                data.mimeType = 'application/octet-stream';
            }

            // Validate file size
            if (data.size < 0) {
                const errorMsg = 'File size cannot be negative';
                this.logger.error(errorMsg, { size: data.size, filename: data.filename });
                throw new BadRequestException(errorMsg);
            }

            // Prepare data for Prisma
            // Ensure path always has a value for backward compatibility
            const pathValue = finalStorageKey || `path-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

            const prismaData = {
                filename: data.filename,
                originalName: data.originalName,
                mimeType: data.mimeType,
                size: data.size,
                path: pathValue, // Always provide a path value for backward compatibility
                storageProvider: data.storageProvider,
                storageKey: finalStorageKey,
                storageUrl: storageUrl,
                category: data.category,
                // Set processing status based on whether upload succeeded
                processingStatus: finalStorageKey.startsWith('failed-upload-') ? 'FAILED' : 'COMPLETED',
            };

            this.logger.log(`Creating file metadata record with data:`, prismaData);

            const fileMetadata = await this.prisma.fileMetadata.create({
                data: prismaData,
            });

            const extendedMetadata = await this.extendFileMetadata(fileMetadata);
            this.logger.log(`File metadata created successfully: ${extendedMetadata.id}`, {
                fileId: extendedMetadata.id,
                storageKey: extendedMetadata.storageKey,
                processingStatus: extendedMetadata.processingStatus,
            });

            return extendedMetadata;
        } catch (error) {
            this.logger.error(`Failed to create file metadata: ${error.message}`, {
                error: error.message,
                stack: error.stack,
                filename: data.filename,
                originalName: data.originalName,
                storageProvider: data.storageProvider,
                storageKey: data.storageKey,
            });

            if (error instanceof BadRequestException) {
                throw error;
            }

            throw new BadRequestException('Failed to create file metadata');
        }
    }

    /**
     * Get file metadata by ID
     * @param id - File metadata ID
     * @param includeRelations - Whether to include related entities
     * @returns File metadata
     */
    async getFileMetadataById(id: string): Promise<ExtendedFileMetadata> {
        try {
            const fileMetadata = await this.prisma.fileMetadata.findUnique({
                where: { id },
            });

            if (!fileMetadata) {
                throw new NotFoundException('File not found');
            }

            return await this.extendFileMetadata(fileMetadata);
        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Failed to get file metadata ${id}: ${error.message}`, error.stack);
            throw new BadRequestException('Failed to retrieve file metadata');
        }
    }

    /**
     * Get file metadata by filename
     * @param filename - File filename
     * @returns File metadata
     */
    async getFileMetadataByFilename(filename: string): Promise<ExtendedFileMetadata> {
        try {
            const fileMetadata = await this.prisma.fileMetadata.findFirst({
                where: { filename },
            });

            if (!fileMetadata) {
                throw new NotFoundException('File not found');
            }

            return await this.extendFileMetadata(fileMetadata);
        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Failed to get file metadata by filename ${filename}: ${error.message}`, error.stack);
            throw new BadRequestException('Failed to retrieve file metadata');
        }
    }

    /**
     * Update file metadata
     * @param id - File metadata ID
     * @param data - Update data
     * @returns Updated file metadata
     */
    async updateFileMetadata(
        id: string,
        data: Partial<{
            originalName: string;
            category?: string;
            securityStatus?: string;
            processingStatus?: string;
        }>,
    ): Promise<ExtendedFileMetadata> {
        try {
            const updateData: any = {};

            if (data.originalName !== undefined) {
                updateData.originalName = data.originalName;
            }

            if (data.category !== undefined) {
                updateData.category = data.category;
            }

            if (data.securityStatus !== undefined) {
                updateData.securityStatus = data.securityStatus;
            }

            if (data.processingStatus !== undefined) {
                updateData.processingStatus = data.processingStatus;
            }

            const fileMetadata = await this.prisma.fileMetadata.update({
                where: { id },
                data: updateData,
            });

            const extendedMetadata = await this.extendFileMetadata(fileMetadata);
            this.logger.log(`File metadata updated: ${id}`);

            return extendedMetadata;
        } catch (error) {
            this.logger.error(`Failed to update file metadata ${id}: ${error.message}`, error.stack);
            throw new BadRequestException('Failed to update file metadata');
        }
    }

    /**
     * Delete file metadata
     * @param id - File metadata ID
     * @returns Deleted file metadata
     */
    async deleteFileMetadata(id: string): Promise<ExtendedFileMetadata> {
        try {
            // First get the file metadata to get the path for cleanup
            const fileMetadata = await this.getFileMetadataById(id);

            // Delete from database
            await this.prisma.fileMetadata.delete({
                where: { id },
            });

            // Note: Physical file deletion is now handled by StorageManagerService
            // The file should be deleted from storage when this method is called

            this.logger.log(`File metadata deleted: ${id}`);
            return fileMetadata;
        } catch (error) {
            this.logger.error(`Failed to delete file metadata ${id}: ${error.message}`, error.stack);
            throw new BadRequestException('Failed to delete file metadata');
        }
    }

    /**
     * Search files based on criteria
     * @param criteria - Search criteria
     * @param pagination - Pagination options
     * @returns Search results with pagination
     */
    async searchFiles(
        criteria: FileSearchCriteria,
        pagination: { page: number; limit: number } = { page: 1, limit: 20 },
    ): Promise<{
        files: ExtendedFileMetadata[];
        total: number;
        page: number;
        limit: number;
        totalPages: number;
    }> {
        try {
            const where: any = {};

            // Build where clause based on criteria
            if (criteria.query) {
                where.OR = [
                    { filename: { contains: criteria.query, mode: 'insensitive' } },
                    { originalName: { contains: criteria.query, mode: 'insensitive' } },
                ];
            }

            if (criteria.uploaderId) {
                where.uploadedById = criteria.uploaderId;
            }

            if (criteria.mimeType) {
                where.mimeType = criteria.mimeType;
            }

            if (criteria.sizeRange) {
                where.size = {};
                if (criteria.sizeRange.min !== undefined) {
                    where.size.gte = criteria.sizeRange.min;
                }
                if (criteria.sizeRange.max !== undefined) {
                    where.size.lte = criteria.sizeRange.max;
                }
            }

            if (criteria.dateRange) {
                where.createdAt = {};
                if (criteria.dateRange.from) {
                    where.createdAt.gte = criteria.dateRange.from;
                }
                if (criteria.dateRange.to) {
                    where.createdAt.lte = criteria.dateRange.to;
                }
            }

            if (criteria.relatedTo) {
                if (criteria.relatedTo.ticketId) {
                    where.relatedTicketId = criteria.relatedTo.ticketId;
                }
                if (criteria.relatedTo.replyId) {
                    where.relatedReplyId = criteria.relatedTo.replyId;
                }
            }

            // Get total count
            const total = await this.prisma.fileMetadata.count({ where });

            // Get paginated results
            const skip = (pagination.page - 1) * pagination.limit;
            const files = await this.prisma.fileMetadata.findMany({
                where,
                skip,
                take: pagination.limit,
                orderBy: { createdAt: 'desc' },
            });

            const extendedFiles = await Promise.all(
                files.map(file => this.extendFileMetadata(file)),
            );

            const totalPages = Math.ceil(total / pagination.limit);

            return {
                files: extendedFiles,
                total,
                page: pagination.page,
                limit: pagination.limit,
                totalPages,
            };
        } catch (error) {
            this.logger.error(`Failed to search files: ${error.message}`, error.stack);
            throw new BadRequestException('Failed to search files');
        }
    }

    /**
     * Get files by user ID
     * @param userId - User ID
     * @param pagination - Pagination options
     * @returns User's files
     */
    async getFilesByUserId(
        userId: string,
        pagination: { page: number; limit: number } = { page: 1, limit: 20 },
    ): Promise<{
        files: ExtendedFileMetadata[];
        total: number;
        page: number;
        limit: number;
        totalPages: number;
    }> {
        return this.searchFiles(
            { uploaderId: userId },
            pagination,
        );
    }

    /**
     * Get file statistics
     * @returns File statistics
     */
    async getFileStatistics(): Promise<{
        totalCount: number;
        totalSize: number;
        byCategory: Record<string, number>;
        byUser: Array<{
            userId: string;
            userName: string;
            fileCount: number;
            totalSize: number;
        }>;
    }> {
        try {
            // Get total count and size
            const aggregate = await this.prisma.fileMetadata.aggregate({
                _count: { id: true },
                _sum: { size: true },
            });

            // This is a simplified version. In a real implementation,
            // you might want to add category fields to the schema
            // and implement more detailed statistics
            const totalCount = aggregate._count.id || 0;
            const totalSize = aggregate._sum.size || 0;

            return {
                totalCount,
                totalSize,
                byCategory: {}, // Would need category field in schema
                byUser: [], // Would need more complex aggregation
            };
        } catch (error) {
            this.logger.error(`Failed to get file statistics: ${error.message}`, error.stack);
            throw new BadRequestException('Failed to get file statistics');
        }
    }

    /**
     * Extend basic file metadata with computed properties
     * @param fileMetadata - Basic file metadata from Prisma
     * @returns Extended file metadata
     */
    private async extendFileMetadata(
        fileMetadata: PrismaFileMetadata & any,
    ): Promise<ExtendedFileMetadata> {
        // Extract extension from filename
        const extension = fileMetadata.filename.split('.').pop() || '';

        // Format file size
        const formattedSize = this.formatFileSize(fileMetadata.size);

        // Determine file category based on MIME type
        const mimeType = fileMetadata.mimeType;
        let category: string = 'other';
        let isImage = false;
        let isDocument = false;

        if (mimeType.startsWith('image/')) {
            category = 'image';
            isImage = true;
        } else if (
            mimeType === 'application/pdf' ||
            mimeType.includes('document') ||
            mimeType.includes('spreadsheet') ||
            mimeType.includes('presentation')
        ) {
            category = 'document';
            isDocument = true;
        } else if (mimeType.startsWith('audio/')) {
            category = 'audio';
        } else if (mimeType.startsWith('video/')) {
            category = 'video';
        } else if (mimeType === 'application/zip' || mimeType.includes('compressed')) {
            category = 'archive';
        }

        // Check if file can be previewed
        const canPreview = isImage || mimeType === 'application/pdf' || mimeType === 'text/plain';

        // Cast storage provider string to enum
        const storageProviderEnum = Object.values(StorageProvider).includes(fileMetadata.storageProvider as StorageProvider)
            ? (fileMetadata.storageProvider as StorageProvider)
            : StorageProvider.LOCAL;

        return {
            ...fileMetadata,
            storageProvider: storageProviderEnum,
            extension,
            formattedSize,
            category: category as any, // Cast to enum type
            isImage,
            isDocument,
            canPreview,
            // Add download URL (would be constructed by controller)
            downloadUrl: `/api/files/${fileMetadata.id}`,
        };
    }

    /**
     * Format file size in human readable format
     */
    private formatFileSize(bytes: number): string {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let size = bytes;
        let unitIndex = 0;

        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }

        return `${size.toFixed(1)} ${units[unitIndex]}`;
    }

    /**
     * Get files by storage provider with pagination
     */
    async getFilesByStorageProvider(
        filters: {
            storageProvider?: string;
            category?: string;
        },
        pagination: { page: number; limit: number } = { page: 1, limit: 20 },
    ): Promise<{
        files: ExtendedFileMetadata[];
        total: number;
        page: number;
        limit: number;
        totalPages: number;
    }> {
        try {
            const where: any = {};

            if (filters.storageProvider) {
                where.storageProvider = filters.storageProvider;
            }

            if (filters.category) {
                where.category = filters.category;
            }

            // Get total count
            const total = await this.prisma.fileMetadata.count({ where });

            // Get paginated results
            const skip = (pagination.page - 1) * pagination.limit;
            const files = await this.prisma.fileMetadata.findMany({
                where,
                skip,
                take: pagination.limit,
                orderBy: { createdAt: 'desc' },
            });

            const extendedFiles = await Promise.all(
                files.map(file => this.extendFileMetadata(file)),
            );

            const totalPages = Math.ceil(total / pagination.limit);

            return {
                files: extendedFiles,
                total,
                page: pagination.page,
                limit: pagination.limit,
                totalPages,
            };
        } catch (error) {
            this.logger.error(`Failed to get files by storage provider: ${error.message}`, error.stack);
            throw new BadRequestException('Failed to get files by storage provider');
        }
    }
}