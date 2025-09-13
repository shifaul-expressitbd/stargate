/**
 * Storage service options and configuration interfaces
 */

import type { ServerSideEncryption, StorageClass } from '@aws-sdk/client-s3';
import { StorageProvider } from './storage.interface';

/**
 * Common storage options for all providers
 */
export interface StorageOptions {
    /** Storage provider type */
    provider: StorageProvider;

    /** Base URL for storage operations */
    baseUrl?: string;

    /** Timeout for storage operations in milliseconds */
    timeout?: number;

    /** Retry configuration */
    retry?: {
        attempts: number;
        delay: number;
        backoff: 'fixed' | 'exponential';
    };

    /** Whether to enable logging */
    enableLogging?: boolean;

    /** Custom metadata to attach to all files */
    defaultMetadata?: Record<string, any>;
}

/**
 * Local storage specific options
 */
export interface LocalStorageOptions extends StorageOptions {
    provider: StorageProvider.LOCAL;

    /** Base directory for file storage */
    baseDir: string;

    /** Directory structure strategy */
    directoryStrategy?: 'flat' | 'date' | 'user' | 'custom';

    /** Custom directory generator */
    directoryGenerator?: (file: any, userId?: string) => string;

    /** File permissions (octal) */
    permissions?: number;

    /** Whether to create directories if they don't exist */
    createDirs?: boolean;
}

/**
 * Cloudinary storage specific options
 */
export interface CloudinaryStorageOptions extends StorageOptions {
    provider: StorageProvider.CLOUDINARY;

    /** Cloudinary cloud name */
    cloudName: string;

    /** Cloudinary API key */
    apiKey: string;

    /** Cloudinary API secret */
    apiSecret: string;

    /** Upload preset */
    uploadPreset?: string;

    /** Folder for uploads */
    folder?: string;

    /** Transformation parameters */
    transformation?: Record<string, any>;

    /** Whether to use secure URLs */
    secure?: boolean;

    /** CDN subdomain */
    cdnSubdomain?: string;
}

/**
 * MinIO storage specific options
 */
export interface MinIOStorageOptions extends StorageOptions {
    provider: StorageProvider.MINIO;

    /** MinIO endpoint */
    endPoint: string;

    /** MinIO port */
    port?: number;

    /** Whether to use SSL */
    useSSL?: boolean;

    /** MinIO access key */
    accessKey: string;

    /** MinIO secret key */
    secretKey: string;

    /** Bucket name */
    bucket: string;

    /** Region */
    region?: string;

    /** Public URL for serving files */
    publicUrl?: string;

    /** Custom metadata */
    metadata?: Record<string, any>;
}

/**
 * S3 storage specific options
 */
export interface S3StorageOptions extends StorageOptions {
    provider: StorageProvider.S3;

    /** AWS region */
    region: string;

    /** AWS access key ID */
    accessKeyId: string;

    /** AWS secret access key */
    secretAccessKey: string;

    /** S3 bucket name */
    bucket: string;

    /** S3 endpoint (for custom endpoints) */
    endpoint?: string;

    /** Whether to use path-style URLs */
    forcePathStyle?: boolean;

    /** S3 storage class */
    storageClass?: StorageClass;

    /** Public URL for serving files */
    publicUrl?: string;

    /** Server-side encryption */
    serverSideEncryption?: ServerSideEncryption;

    /** Custom metadata */
    metadata?: Record<string, any>;
}

/**
 * Cloudflare R2 storage specific options
 */
export interface R2StorageOptions extends StorageOptions {
    provider: StorageProvider.CLOUDFLARE_R2;

    /** Cloudflare account ID */
    accountId: string;

    /** Cloudflare R2 access key ID */
    accessKeyId: string;

    /** Cloudflare R2 secret access key */
    secretAccessKey: string;

    /** R2 bucket name */
    bucket: string;

    /** R2 endpoint URL (e.g., https://<accountId>.r2.cloudflarestorage.com) */
    endpoint: string;

    /** Public URL for serving files */
    publicUrl?: string;

    /** Custom metadata */
    metadata?: Record<string, any>;
}

/**
 * Google Cloud Storage specific options
 */
export interface GoogleCloudStorageOptions extends StorageOptions {
    provider: StorageProvider.GOOGLE_CLOUD;

    /** GCP project ID */
    projectId: string;

    /** GCS bucket name */
    bucket: string;

    /** Service account key file path */
    keyFilename?: string;

    /** Service account credentials */
    credentials?: {
        type: string;
        project_id: string;
        private_key_id: string;
        private_key: string;
        client_email: string;
        client_id: string;
        auth_uri: string;
        token_uri: string;
        auth_provider_x509_cert_url: string;
        client_x509_cert_url: string;
    };

    /** Public URL for serving files */
    publicUrl?: string;

    /** Storage class */
    storageClass?: string;

    /** Whether to enable versioning */
    versioning?: boolean;

    /** Custom metadata */
    metadata?: Record<string, any>;
}

/**
 * Union type for all storage options
 */
export type AllStorageOptions =
    | LocalStorageOptions
    | CloudinaryStorageOptions
    | MinIOStorageOptions
    | S3StorageOptions
    | R2StorageOptions
    | GoogleCloudStorageOptions;

/**
 * Storage configuration for multiple providers
 */
export interface StorageConfig {
    /** Default storage provider */
    defaultProvider: StorageProvider;

    /** Configuration for each provider */
    providers: Record<StorageProvider, AllStorageOptions>;

    /** Global storage options */
    global?: {
        /** Global timeout */
        timeout?: number;

        /** Global retry configuration */
        retry?: {
            attempts: number;
            delay: number;
            backoff: 'fixed' | 'exponential';
        };

        /** Global logging */
        enableLogging?: boolean;

        /** Global metadata */
        defaultMetadata?: Record<string, any>;
    };
}