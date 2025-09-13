/**
 * File query Data Transfer Objects
 */

import { ApiPropertyOptional } from '@nestjs/swagger';
import { Transform, Type } from 'class-transformer';
import {
    IsArray,
    IsDate,
    IsIn,
    IsNumber,
    IsOptional,
    IsString,
    IsUUID,
    Max,
    MaxLength,
    Min
} from 'class-validator';
import { FileCategory, FileProcessingStatus, FileSecurityStatus } from '../interfaces/file-metadata.interface';
import { StorageProvider } from '../interfaces/storage.interface';

/**
 * DTO for querying files with pagination and filtering
 */
export class FileQueryDto {
    @ApiPropertyOptional({
        description: 'Search query for filename or content',
        example: 'document',
    })
    @IsOptional()
    @IsString()
    @MaxLength(255)
    query?: string;

    @ApiPropertyOptional({
        description: 'Filter by file category',
        enum: FileCategory,
        example: FileCategory.DOCUMENT,
    })
    @IsOptional()
    @IsIn(Object.values(FileCategory))
    category?: FileCategory;

    @ApiPropertyOptional({
        description: 'Filter by MIME type',
        example: 'application/pdf',
    })
    @IsOptional()
    @IsString()
    mimeType?: string;

    @ApiPropertyOptional({
        description: 'Filter by uploader ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @IsOptional()
    @IsUUID()
    uploaderId?: string;

    @ApiPropertyOptional({
        description: 'Filter by related ticket ID',
        example: '123e4567-e89b-12d3-a456-426614174001',
    })
    @IsOptional()
    @IsUUID()
    ticketId?: string;

    @ApiPropertyOptional({
        description: 'Filter by related reply ID',
        example: '123e4567-e89b-12d3-a456-426614174002',
    })
    @IsOptional()
    @IsUUID()
    replyId?: string;

    @ApiPropertyOptional({
        description: 'Minimum file size in bytes',
        example: 1024,
        minimum: 0,
    })
    @IsOptional()
    @Type(() => Number)
    @IsNumber()
    @Min(0)
    minSize?: number;

    @ApiPropertyOptional({
        description: 'Maximum file size in bytes',
        example: 10485760,
        minimum: 0,
    })
    @IsOptional()
    @Type(() => Number)
    @IsNumber()
    @Min(0)
    maxSize?: number;

    @ApiPropertyOptional({
        description: 'Filter by upload date from (ISO string)',
        example: '2024-01-01T00:00:00.000Z',
    })
    @IsOptional()
    @Transform(({ value }) => value ? new Date(value) : undefined)
    @IsDate()
    dateFrom?: Date;

    @ApiPropertyOptional({
        description: 'Filter by upload date to (ISO string)',
        example: '2024-12-31T23:59:59.999Z',
    })
    @IsOptional()
    @Transform(({ value }) => value ? new Date(value) : undefined)
    @IsDate()
    dateTo?: Date;

    @ApiPropertyOptional({
        description: 'Filter by security status',
        enum: FileSecurityStatus,
        example: FileSecurityStatus.SAFE,
    })
    @IsOptional()
    @IsIn(Object.values(FileSecurityStatus))
    securityStatus?: FileSecurityStatus;

    @ApiPropertyOptional({
        description: 'Filter by processing status',
        enum: FileProcessingStatus,
        example: FileProcessingStatus.PROCESSED,
    })
    @IsOptional()
    @IsIn(Object.values(FileProcessingStatus))
    processingStatus?: FileProcessingStatus;

    @ApiPropertyOptional({
        description: 'Filter by storage provider',
        enum: StorageProvider,
        example: StorageProvider.S3,
    })
    @IsOptional()
    @IsIn(Object.values(StorageProvider))
    storageProvider?: StorageProvider;

    @ApiPropertyOptional({
        description: 'Page number for pagination (1-based)',
        example: 1,
        minimum: 1,
        default: 1,
    })
    @IsOptional()
    @Type(() => Number)
    @IsNumber()
    @Min(1)
    page?: number = 1;

    @ApiPropertyOptional({
        description: 'Number of items per page',
        example: 20,
        minimum: 1,
        maximum: 100,
        default: 20,
    })
    @IsOptional()
    @Type(() => Number)
    @IsNumber()
    @Min(1)
    @Max(100)
    limit?: number = 20;

    @ApiPropertyOptional({
        description: 'Sort field',
        example: 'createdAt',
        enum: ['createdAt', 'filename', 'size', 'mimeType'],
    })
    @IsOptional()
    @IsIn(['createdAt', 'filename', 'size', 'mimeType'])
    sortBy?: 'createdAt' | 'filename' | 'size' | 'mimeType';

    @ApiPropertyOptional({
        description: 'Sort order',
        example: 'desc',
        enum: ['asc', 'desc'],
    })
    @IsOptional()
    @IsIn(['asc', 'desc'])
    sortOrder?: 'asc' | 'desc';

    @ApiPropertyOptional({
        description: 'Include related entities in response (comma-separated or array)',
        example: ['uploader', 'ticket'],
        enum: ['uploader', 'ticket', 'reply'],
    })
    @IsOptional()
    @Transform(({ value }) => {
        if (!value) return undefined;
        if (Array.isArray(value)) return value;
        if (typeof value === 'string') {
            return value.split(',').map((item: string) => item.trim()).filter(Boolean);
        }
        return undefined;
    })
    @IsArray()
    @IsString({ each: true })
    @IsIn(['uploader', 'ticket', 'reply'], { each: true })
    include?: string[];
}

/**
 * DTO for file list response with pagination
 */
export class FileListResponseDto {
    @ApiPropertyOptional({
        description: 'Array of file metadata',
        type: 'array',
    })
    files: any[]; // Will be FileMetadataDto[]

    @ApiPropertyOptional({
        description: 'Pagination metadata',
        type: 'object',
        properties: {
            page: { type: 'number' },
            limit: { type: 'number' },
            total: { type: 'number' },
            totalPages: { type: 'number' },
            hasNext: { type: 'boolean' },
            hasPrev: { type: 'boolean' },
        },
    })
    pagination?: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
        hasNext: boolean;
        hasPrev: boolean;
    };

    @ApiPropertyOptional({
        description: 'Applied filters',
        example: {
            category: 'document',
            mimeType: 'application/pdf',
            storageProvider: 's3',
            uploaderId: '123e4567-e89b-12d3-a456-426614174000',
        },
    })
    filters?: Record<string, any>;

    @ApiPropertyOptional({
        description: 'Sorting information',
        example: {
            field: 'createdAt',
            order: 'desc',
        },
    })
    sort?: {
        field: string;
        order: string;
    };
}

/**
 * DTO for file search suggestions
 */
export class FileSearchSuggestionDto {
    @ApiPropertyOptional({
        description: 'Search query',
        example: 'document',
    })
    query?: string;

    @ApiPropertyOptional({
        description: 'Suggested file categories',
        example: ['document', 'image'],
    })
    categories?: FileCategory[];

    @ApiPropertyOptional({
        description: 'Suggested MIME types',
        example: ['application/pdf', 'image/jpeg'],
    })
    mimeTypes?: string[];

    @ApiPropertyOptional({
        description: 'Suggested uploader names',
        example: ['John Doe', 'Jane Smith'],
    })
    uploaderNames?: string[];

    @ApiPropertyOptional({
        description: 'Total number of matching files',
        example: 150,
    })
    totalMatches?: number;
}

/**
 * DTO for bulk file operations
 */
export class BulkFileOperationDto {
    @ApiPropertyOptional({
        description: 'Array of file IDs to operate on',
        example: [
            '123e4567-e89b-12d3-a456-426614174000',
            '123e4567-e89b-12d3-a456-426614174001',
        ],
    })
    @IsArray()
    @IsUUID('4', { each: true })
    fileIds: string[];

    @ApiPropertyOptional({
        description: 'Operation to perform',
        example: 'delete',
        enum: ['delete', 'move', 'update_metadata'],
    })
    @IsString()
    @IsIn(['delete', 'move', 'update_metadata'])
    operation: 'delete' | 'move' | 'update_metadata';

    @ApiPropertyOptional({
        description: 'Additional parameters for the operation',
        example: {
            category: 'archive',
            securityStatus: 'safe',
        },
    })
    @IsOptional()
    parameters?: Record<string, any>;
}

/**
 * DTO for bulk file operation response
 */
export class BulkFileOperationResponseDto {
    @ApiPropertyOptional({
        description: 'Number of files successfully processed',
        example: 5,
    })
    processed: number;

    @ApiPropertyOptional({
        description: 'Number of files that failed to process',
        example: 1,
    })
    failed: number;

    @ApiPropertyOptional({
        description: 'Total processing time in milliseconds',
        example: 2500,
    })
    duration: number;

    @ApiPropertyOptional({
        description: 'Errors for failed operations',
        type: 'array',
        items: {
            type: 'object',
            properties: {
                fileId: { type: 'string' },
                filename: { type: 'string' },
                error: { type: 'string' },
            },
        },
    })
    errors?: Array<{
        fileId: string;
        filename: string;
        error: string;
    }>;

    @ApiPropertyOptional({
        description: 'Whether the operation was successful for all files',
        example: false,
    })
    success: boolean;
}