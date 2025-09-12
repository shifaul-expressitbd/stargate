/**
 * Storage service interfaces and types
 * Defines the contract for all storage backends
 */


/**
 * Storage provider types
 */
export enum StorageProvider {
    LOCAL = 'local',
    CLOUDINARY = 'cloudinary',
    MINIO = 'minio',
    S3 = 's3',
    GOOGLE_CLOUD = 'google_cloud',
}

/**
 * File upload result
 */
export interface StorageUploadResult {
    /** Unique identifier for the stored file */
    fileId: string;

    /** File key/path in the storage backend */
    key: string;

    /** Public URL for accessing the file */
    url: string;

    /** File metadata */
    metadata: {
        size: number;
        mimeType: string;
        filename: string;
        uploadedAt: Date;
    };

    /** Provider-specific metadata */
    providerMetadata?: Record<string, any>;

    /** Whether the upload was successful */
    success: boolean;

    /** Error message if upload failed */
    error?: string;

    /** Detailed error information for debugging */
    errorDetails?: Record<string, any>;
}

/**
 * File download/stream result
 */
export interface StorageDownloadResult {
    /** File stream for reading */
    stream?: ReadableStream | NodeJS.ReadableStream;

    /** File metadata */
    metadata?: {
        size: number;
        mimeType: string;
        lastModified?: Date;
    };

    /** Whether the download was successful */
    success: boolean;

    /** Error message if download failed */
    error?: string;
}

/**
 * File deletion result
 */
export interface StorageDeleteResult {
    /** Whether the deletion was successful */
    success: boolean;

    /** Error message if deletion failed */
    error?: string;
}

/**
 * File existence check result
 */
export interface StorageExistsResult {
    /** Whether the file exists */
    exists: boolean;

    /** File metadata if exists */
    metadata?: {
        size: number;
        mimeType: string;
        lastModified?: Date;
    };
}

/**
 * File URL generation result
 */
export interface StorageUrlResult {
    /** Generated URL */
    url: string;

    /** Whether URL generation was successful */
    success: boolean;

    /** Error message if URL generation failed */
    error?: string;

    /** URL expiration time if applicable */
    expiresAt?: Date;
}

/**
 * Storage provider capabilities
 */
export interface StorageCapabilities {
    /** Whether the provider supports resumable uploads */
    resumableUpload: boolean;

    /** Whether the provider supports signed URLs */
    signedUrls: boolean;

    /** Whether the provider supports CDN */
    cdnIntegration: boolean;

    /** Whether the provider supports versioning */
    versioning: boolean;

    /** Whether the provider supports metadata */
    customMetadata: boolean;

    /** Maximum file size supported */
    maxFileSize?: number;

    /** Supported storage classes */
    storageClasses?: string[];

    /** Provider-specific features */
    features?: Record<string, any>;
}

/**
 * Storage provider health check result
 */
export interface StorageHealthResult {
    /** Whether the provider is healthy */
    healthy: boolean;

    /** Response time in milliseconds */
    responseTime?: number;

    /** Error message if unhealthy */
    error?: string;

    /** Additional health metrics */
    metrics?: Record<string, any>;
}