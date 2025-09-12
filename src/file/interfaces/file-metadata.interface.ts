/**
 * File metadata interfaces and types
 * Extends the Prisma FileMetadata model with additional computed properties
 */

import { FileMetadata as PrismaFileMetadata } from '@prisma/client';
import { StorageProvider } from './storage.interface';

/**
 * Extended file metadata interface with additional computed properties
 */
export interface ExtendedFileMetadata extends Omit<PrismaFileMetadata, 'storageProvider'> {
    /** Storage provider enum */
    storageProvider: StorageProvider;
    /** File extension extracted from filename */
    extension?: string;

    /** Human-readable file size */
    formattedSize?: string;

    /** Whether file is an image */
    isImage?: boolean;

    /** Whether file is a document */
    isDocument?: boolean;

    /** File category (image, document, archive, etc.) */
    category: FileCategory | null;

    /** Preview/thumbnail URL if available */
    previewUrl?: string;

    /** Download URL */
    downloadUrl?: string;

    /** Whether file can be previewed in browser */
    canPreview?: boolean;

    /** File security status */
    securityStatus: FileSecurityStatus | null;

    /** Processing status */
    processingStatus: FileProcessingStatus | null;

    /** Associated user information */
    uploader?: {
        id: string;
        email: string;
        name: string;
    };

    /** Associated ticket information */
    relatedTicket?: {
        id: string;
        title: string;
    };

    /** Associated reply information */
    relatedReply?: {
        id: string;
        content: string;
    };
}

/**
 * File category enumeration
 */
export enum FileCategory {
    IMAGE = 'image',
    DOCUMENT = 'document',
    SPREADSHEET = 'spreadsheet',
    PRESENTATION = 'presentation',
    ARCHIVE = 'archive',
    AUDIO = 'audio',
    VIDEO = 'video',
    CODE = 'code',
    TEXT = 'text',
    OTHER = 'other',
}

/**
 * File security status
 */
export enum FileSecurityStatus {
    SAFE = 'safe',
    SUSPICIOUS = 'suspicious',
    MALICIOUS = 'malicious',
    PENDING_SCAN = 'pending_scan',
    SCAN_FAILED = 'scan_failed',
}

/**
 * File processing status
 */
export enum FileProcessingStatus {
    UPLOADED = 'uploaded',
    PROCESSING = 'processing',
    PROCESSED = 'processed',
    FAILED = 'failed',
    QUARANTINED = 'quarantined',
}

/**
 * File statistics interface
 */
export interface FileStatistics {
    /** Total number of files */
    totalCount: number;

    /** Total size of all files in bytes */
    totalSize: number;

    /** Formatted total size */
    formattedTotalSize: string;

    /** Files by category */
    byCategory: Record<FileCategory, number>;

    /** Files by user */
    byUser: Array<{
        userId: string;
        userName: string;
        fileCount: number;
        totalSize: number;
    }>;

    /** Recent uploads */
    recentUploads: ExtendedFileMetadata[];

    /** Storage usage over time */
    usageOverTime: Array<{
        date: string;
        size: number;
        count: number;
    }>;
}

/**
 * File upload result interface
 */
export interface FileUploadResult {
    /** Successfully uploaded files */
    files: ExtendedFileMetadata[];

    /** Failed uploads with error messages */
    failed: Array<{
        originalName: string;
        error: string;
    }>;

    /** Total uploaded size */
    totalSize: number;

    /** Upload duration in milliseconds */
    duration: number;

    /** Whether all files were uploaded successfully */
    success: boolean;
}

/**
 * File search/filter criteria
 */
export interface FileSearchCriteria {
    /** Search query */
    query?: string;

    /** Filter by category */
    category?: FileCategory;

    /** Filter by MIME type */
    mimeType?: string;

    /** Filter by uploader */
    uploaderId?: string;

    /** Filter by size range */
    sizeRange?: {
        min?: number;
        max?: number;
    };

    /** Filter by date range */
    dateRange?: {
        from?: Date;
        to?: Date;
    };

    /** Filter by security status */
    securityStatus?: FileSecurityStatus;

    /** Filter by processing status */
    processingStatus?: FileProcessingStatus;

    /** Related entity filters */
    relatedTo?: {
        ticketId?: string;
        replyId?: string;
    };
}

/**
 * File operation result interface
 */
export interface FileOperationResult {
    /** Whether the operation was successful */
    success: boolean;

    /** File metadata if applicable */
    file?: ExtendedFileMetadata;

    /** Error message if operation failed */
    error?: string;

    /** Additional metadata about the operation */
    metadata?: Record<string, any>;
}

/**
 * File cleanup result interface
 */
export interface FileCleanupResult {
    /** Number of files processed */
    processed: number;

    /** Number of files deleted */
    deleted: number;

    /** Number of files that failed to delete */
    failed: number;

    /** Total space freed in bytes */
    spaceFreed: number;

    /** Formatted space freed */
    formattedSpaceFreed: string;

    /** Errors encountered during cleanup */
    errors: Array<{
        fileId: string;
        filename: string;
        error: string;
    }>;

    /** Whether cleanup was in dry-run mode */
    dryRun: boolean;
}