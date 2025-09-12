/**
 * File upload Data Transfer Objects
 */

import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
    IsBoolean,
    IsIn,
    IsOptional,
    IsUUID
} from 'class-validator';
import { FileCategory } from '../interfaces/file-metadata.interface';
import { StorageProvider } from '../interfaces/storage.interface';

/**
 * DTO for file upload request
 */
export class FileUploadDto {
    @ApiPropertyOptional({
        description: 'Optional ticket ID to associate uploaded files with',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @IsOptional()
    @IsUUID()
    ticketId?: string;

    @ApiPropertyOptional({
        description: 'Optional reply ID to associate uploaded files with',
        example: '123e4567-e89b-12d3-a456-426614174001',
    })
    @IsOptional()
    @IsUUID()
    replyId?: string;

    @ApiPropertyOptional({
        description: 'Custom metadata for uploaded files',
        example: { category: 'document', tags: ['important', 'review'] },
    })
    @IsOptional()
    @Transform(({ value }) => {
        if (typeof value === 'string') {
            try {
                return JSON.parse(value);
            } catch {
                return {};
            }
        }
        return value;
    })
    metadata?: Record<string, any>;

    @ApiPropertyOptional({
        description: 'Whether to generate unique filenames',
        default: true,
        example: true,
    })
    @IsOptional()
    @IsBoolean()
    @Transform(({ value }) => {
        if (value === 'true') return true;
        if (value === 'false') return false;
        return value;
    })
    preserveOriginalName?: boolean = true;

    @ApiPropertyOptional({
        description: 'File category',
        enum: FileCategory,
        example: FileCategory.DOCUMENT,
    })
    @IsOptional()
    @IsIn(Object.values(FileCategory))
    category?: FileCategory;

    @ApiPropertyOptional({
        description: 'Preferred storage provider for the uploaded files. If not specified, the system will automatically select the optimal provider based on file type, size, and configured priorities.',
        enum: StorageProvider,
        example: StorageProvider.S3,
    })
    @IsOptional()
    @IsIn(Object.values(StorageProvider))
    storageProvider?: StorageProvider;
}

/**
 * DTO for file upload response
 */
export class FileUploadResponseDto {
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

    @ApiProperty({
        description: 'File extension',
        example: 'pdf',
    })
    extension?: string;

    @ApiProperty({
        description: 'Formatted file size',
        example: '1 MB',
    })
    formattedSize?: string;

    @ApiProperty({
        description: 'File category',
        enum: FileCategory,
        example: FileCategory.DOCUMENT,
    })
    category?: FileCategory;

    @ApiProperty({
        description: 'Download URL',
        example: '/api/files/123e4567-e89b-12d3-a456-426614174000',
    })
    downloadUrl?: string;

    @ApiProperty({
        description: 'Upload timestamp',
        example: '2024-01-15T10:30:00.000Z',
    })
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
 * DTO for multiple file upload response
 */
export class MultipleFileUploadResponseDto {
    @ApiProperty({
        description: 'Successfully uploaded files',
        type: [FileUploadResponseDto],
    })
    files: FileUploadResponseDto[];

    @ApiProperty({
        description: 'Failed uploads',
        type: 'array',
        items: {
            type: 'object',
            properties: {
                originalName: { type: 'string' },
                error: { type: 'string' },
            },
        },
    })
    failed: Array<{
        originalName: string;
        error: string;
    }>;

    @ApiProperty({
        description: 'Total size of uploaded files in bytes',
        example: 5120000,
    })
    totalSize: number;

    @ApiProperty({
        description: 'Upload processing time in milliseconds',
        example: 1500,
    })
    duration: number;

    @ApiProperty({
        description: 'Whether all files were uploaded successfully',
        example: true,
    })
    success: boolean;

    @ApiPropertyOptional({
        description: 'Summary of storage providers used for uploaded files',
        example: {
            local: 2,
            s3: 1,
            cloudinary: 0
        },
    })
    storageProviderSummary?: Record<StorageProvider, number>;
}

/**
 * DTO for file validation errors
 */
export class FileValidationErrorDto {
    @ApiProperty({
        description: 'Original filename that failed validation',
        example: 'malicious.exe',
    })
    filename: string;

    @ApiProperty({
        description: 'Validation error message',
        example: 'File type not allowed. Allowed types: image/jpeg, image/png',
    })
    error: string;

    @ApiPropertyOptional({
        description: 'Error code for programmatic handling',
        example: 'INVALID_FILE_TYPE',
    })
    code?: string;
}