/**
 * File operation options and configuration interfaces
 */

/**
 * Simplified Multer file interface for our use case
 */
export interface MulterFile {
    fieldname: string;
    originalname: string;
    encoding: string;
    mimetype: string;
    size: number;
    destination: string;
    filename: string;
    path: string;
    buffer: Buffer;
}


/**
 * Options for file upload operations
 */
export interface FileUploadOptions {
    /** Maximum file size in bytes */
    maxSize?: number;

    /** Allowed MIME types */
    allowedTypes?: string[];

    /** Maximum number of files allowed */
    maxFilesCount?: number;

    /** Destination directory for uploads */
    destination?: string;

    /** Whether to generate unique filenames */
    preserveOriginalName?: boolean;

    /** Custom filename generator function */
    filenameGenerator?: (originalName: string, file: MulterFile) => string;

    /** File validation options */
    validation?: FileValidationOptions;
}

/**
 * File validation configuration options
 */
export interface FileValidationOptions {
    /** Check file type against allowed types */
    checkMimeType?: boolean;

    /** Check file extension */
    checkExtension?: boolean;

    /** Perform security checks (magic number validation) */
    securityCheck?: boolean;

    /** Maximum filename length */
    maxFilenameLength?: number;

    /** Forbidden filename patterns */
    forbiddenPatterns?: RegExp[];

    /** Maximum file size in bytes */
    maxSize?: number;

    /** Allowed MIME types */
    allowedTypes?: string[];
}

/**
 * Options for file storage operations
 */
export interface FileStorageOptions {
    /** Base directory for file storage */
    baseDir?: string;

    /** Directory structure strategy */
    directoryStrategy?: 'flat' | 'date' | 'user' | 'custom';

    /** Custom directory generator */
    directoryGenerator?: (file: MulterFile, userId?: string) => string;

    /** File permissions (octal) */
    permissions?: number;

    /** Whether to create directories if they don't exist */
    createDirs?: boolean;
}

/**
 * Options for file download/streaming operations
 */
export interface FileDownloadOptions {
    /** Whether to force download (set Content-Disposition) */
    forceDownload?: boolean;

    /** Custom filename for download */
    downloadName?: string;

    /** Buffer size for streaming */
    bufferSize?: number;

    /** Range request support */
    supportRanges?: boolean;
}

/**
 * File cleanup options
 */
export interface FileCleanupOptions {
    /** Maximum age in days for file cleanup */
    maxAgeDays?: number;

    /** Cron schedule for cleanup (if scheduled) */
    cronSchedule?: string;

    /** Whether cleanup is enabled */
    enabled?: boolean;

    /** Dry run mode (don't actually delete files) */
    dryRun?: boolean;

    /** Custom cleanup criteria */
    criteria?: FileCleanupCriteria;
}

/**
 * Criteria for file cleanup operations
 */
export interface FileCleanupCriteria {
    /** Minimum file age in milliseconds */
    olderThan?: number;

    /** File types to clean up */
    fileTypes?: string[];

    /** Exclude files matching these patterns */
    excludePatterns?: RegExp[];

    /** Only clean files from specific directories */
    includeDirs?: string[];

    /** Exclude files from specific directories */
    excludeDirs?: string[];
}

/**
 * File query options for listing/searching files
 */
export interface FileQueryOptions {
    /** User ID to filter files */
    userId?: string;

    /** File types to filter */
    mimeTypes?: string[];

    /** Date range for file creation */
    dateFrom?: Date;
    dateTo?: Date;

    /** Pagination options */
    pagination?: {
        page?: number;
        limit?: number;
        offset?: number;
    };

    /** Sorting options */
    sort?: {
        field?: 'createdAt' | 'filename' | 'size' | 'mimeType';
        order?: 'asc' | 'desc';
    };

    /** Search query */
    search?: string;
}

/**
 * File access permissions
 */
export interface FilePermissions {
    /** Whether the user can read/download the file */
    canRead: boolean;

    /** Whether the user can update file metadata */
    canUpdate: boolean;

    /** Whether the user can delete the file */
    canDelete: boolean;

    /** Whether the user owns the file */
    isOwner: boolean;

    /** Additional roles/permissions */
    roles?: string[];
}