/**
 * File metadata Data Transfer Objects
 */

import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
    IsIn,
    IsOptional,
    IsString,
    MaxLength
} from 'class-validator';
import {
    FileCategory,
    FileProcessingStatus,
    FileSecurityStatus,
} from '../interfaces/file-metadata.interface';
import { StorageProvider } from '../interfaces/storage.interface';

/**
 * DTO for file metadata response
 */
export class FileMetadataDto {
    @ApiProperty({
        description: 'Unique file identifier',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    id: string;

    @ApiProperty({
        description: 'Generated filename',
        example: 'document_1234567890.pdf',
    })
    filename: string;

    @ApiProperty({
        description: 'Original filename from upload',
        example: 'my-document.pdf',
    })
    originalName: string;

    @ApiProperty({
        description: 'File MIME type',
        example: 'application/pdf',
    })
    mimeType: string;

    @ApiProperty({
        description: 'File size in bytes',
        example: 1024000,
    })
    size: number;

    @ApiProperty({
        description: 'File path on server',
        example: 'uploads/2024/01/document_1234567890.pdf',
    })
    path: string;

    @ApiPropertyOptional({
        description: 'File extension',
        example: 'pdf',
    })
    extension?: string;

    @ApiPropertyOptional({
        description: 'Formatted file size',
        example: '1 MB',
    })
    formattedSize?: string;

    @ApiPropertyOptional({
        description: 'File category',
        enum: FileCategory,
        example: FileCategory.DOCUMENT,
    })
    category?: FileCategory;

    @ApiPropertyOptional({
        description: 'Whether file is an image',
        example: false,
    })
    isImage?: boolean;

    @ApiPropertyOptional({
        description: 'Whether file is a document',
        example: true,
    })
    isDocument?: boolean;

    @ApiPropertyOptional({
        description: 'Whether file can be previewed in browser',
        example: true,
    })
    canPreview?: boolean;

    @ApiPropertyOptional({
        description: 'Preview/thumbnail URL if available',
        example: '/api/files/123e4567-e89b-12d3-a456-426614174000/preview',
    })
    previewUrl?: string;

    @ApiProperty({
        description: 'Download URL',
        example: '/api/files/123e4567-e89b-12d3-a456-426614174000',
    })
    downloadUrl: string;

    @ApiPropertyOptional({
        description: 'File security status',
        enum: FileSecurityStatus,
        example: FileSecurityStatus.SAFE,
    })
    securityStatus?: FileSecurityStatus;

    @ApiPropertyOptional({
        description: 'File processing status',
        enum: FileProcessingStatus,
        example: FileProcessingStatus.PROCESSED,
    })
    processingStatus?: FileProcessingStatus;

    @ApiProperty({
        description: 'Uploader user ID',
        example: '123e4567-e89b-12d3-a456-426614174001',
    })
    uploadedById: string;

    @ApiPropertyOptional({
        description: 'Uploader information',
        type: 'object',
        properties: {
            id: { type: 'string' },
            email: { type: 'string' },
            name: { type: 'string' },
        },
    })
    uploader?: {
        id: string;
        email: string;
        name: string;
    };

    @ApiPropertyOptional({
        description: 'Related ticket ID',
        example: '123e4567-e89b-12d3-a456-426614174002',
    })
    relatedTicketId?: string;

    @ApiPropertyOptional({
        description: 'Related ticket information',
        type: 'object',
        properties: {
            id: { type: 'string' },
            title: { type: 'string' },
        },
    })
    relatedTicket?: {
        id: string;
        title: string;
    };

    @ApiPropertyOptional({
        description: 'Related reply ID',
        example: '123e4567-e89b-12d3-a456-426614174003',
    })
    relatedReplyId?: string;

    @ApiPropertyOptional({
        description: 'Related reply information',
        type: 'object',
        properties: {
            id: { type: 'string' },
            content: { type: 'string', maxLength: 100 },
        },
    })
    relatedReply?: {
        id: string;
        content: string;
    };

    @ApiProperty({
        description: 'File creation timestamp',
        example: '2024-01-15T10:30:00.000Z',
    })
    @Type(() => Date)
    createdAt: Date;

    @ApiProperty({
        description: 'Storage provider used for this file',
        enum: StorageProvider,
        example: StorageProvider.S3,
    })
    storageProvider: StorageProvider;

    @ApiPropertyOptional({
        description: 'Storage-specific metadata and URLs',
        example: {
            bucket: 'my-files-bucket',
            region: 'us-east-1',
            key: 'uploads/2024/01/document_1234567890.pdf',
            publicUrl: 'https://my-files-bucket.s3.amazonaws.com/uploads/2024/01/document_1234567890.pdf',
            signedUrl: 'https://my-files-bucket.s3.amazonaws.com/uploads/2024/01/document_1234567890.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&...'
        },
    })
    storageMetadata?: Record<string, any>;
}

/**
 * DTO for updating file metadata
 */
export class UpdateFileMetadataDto {
    @ApiPropertyOptional({
        description: 'Original filename to update',
        example: 'updated-document-name.pdf',
        maxLength: 255,
    })
    @IsOptional()
    @IsString()
    @MaxLength(255)
    originalName?: string;

    @ApiPropertyOptional({
        description: 'File category',
        enum: FileCategory,
        example: FileCategory.DOCUMENT,
    })
    @IsOptional()
    @IsIn(Object.values(FileCategory))
    category?: FileCategory;

    @ApiPropertyOptional({
        description: 'File security status',
        enum: FileSecurityStatus,
        example: FileSecurityStatus.SAFE,
    })
    @IsOptional()
    @IsIn(Object.values(FileSecurityStatus))
    securityStatus?: FileSecurityStatus;

    @ApiPropertyOptional({
        description: 'File processing status',
        enum: FileProcessingStatus,
        example: FileProcessingStatus.PROCESSED,
    })
    @IsOptional()
    @IsIn(Object.values(FileProcessingStatus))
    processingStatus?: FileProcessingStatus;

    @ApiPropertyOptional({
        description: 'Custom metadata',
        example: { tags: ['important', 'reviewed'], description: 'Updated description' },
    })
    @IsOptional()
    metadata?: Record<string, any>;
}

/**
 * DTO for file permissions response
 */
export class FilePermissionsDto {
    @ApiProperty({
        description: 'Whether the user can read/download the file',
        example: true,
    })
    canRead: boolean;

    @ApiProperty({
        description: 'Whether the user can update file metadata',
        example: true,
    })
    canUpdate: boolean;

    @ApiProperty({
        description: 'Whether the user can delete the file',
        example: false,
    })
    canDelete: boolean;

    @ApiProperty({
        description: 'Whether the user owns the file',
        example: true,
    })
    isOwner: boolean;

    @ApiPropertyOptional({
        description: 'Additional roles/permissions',
        example: ['admin', 'moderator'],
    })
    roles?: string[];
}

/**
 * DTO for file statistics
 */
export class FileStatisticsDto {
    @ApiProperty({
        description: 'Total number of files',
        example: 1250,
    })
    totalCount: number;

    @ApiProperty({
        description: 'Total size of all files in bytes',
        example: 1073741824,
    })
    totalSize: number;

    @ApiProperty({
        description: 'Formatted total size',
        example: '1 GB',
    })
    formattedTotalSize: string;

    @ApiProperty({
        description: 'Files by category',
        example: {
            document: 450,
            image: 300,
            archive: 150,
            other: 350,
        },
    })
    byCategory: Record<FileCategory, number>;

    @ApiProperty({
        description: 'Files by user',
        type: 'array',
        items: {
            type: 'object',
            properties: {
                userId: { type: 'string' },
                userName: { type: 'string' },
                fileCount: { type: 'number' },
                totalSize: { type: 'number' },
            },
        },
    })
    byUser: Array<{
        userId: string;
        userName: string;
        fileCount: number;
        totalSize: number;
    }>;

    @ApiProperty({
        description: 'Recent uploads',
        type: [FileMetadataDto],
    })
    recentUploads: FileMetadataDto[];

    @ApiProperty({
        description: 'Storage usage over time',
        type: 'array',
        items: {
            type: 'object',
            properties: {
                date: { type: 'string' },
                size: { type: 'number' },
                count: { type: 'number' },
            },
        },
    })
    usageOverTime: Array<{
        date: string;
        size: number;
        count: number;
    }>;
}