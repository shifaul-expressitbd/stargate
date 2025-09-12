/**
 * Storage Service Interface
 * Defines the contract that all storage backends must implement
 */

import { MulterFile } from './file-options.interface';
import {
    StorageCapabilities,
    StorageDeleteResult,
    StorageDownloadResult,
    StorageExistsResult,
    StorageHealthResult,
    StorageUploadResult,
    StorageUrlResult,
} from './storage.interface';

/**
 * Main storage service interface
 * All storage backends must implement this interface
 */
export interface IStorageService {
    /**
     * Upload a file to the storage backend
     * @param file - File to upload
     * @param key - Optional key/path for the file
     * @param options - Upload options
     * @returns Promise with upload result
     */
    upload(
        file: MulterFile | Buffer,
        key?: string,
        options?: {
            mimeType?: string;
            metadata?: Record<string, any>;
            permissions?: string;
            expiresAt?: Date;
        }
    ): Promise<StorageUploadResult>;

    /**
     * Download a file from the storage backend
     * @param key - File key/path
     * @returns Promise with download result
     */
    download(key: string): Promise<StorageDownloadResult>;

    /**
     * Delete a file from the storage backend
     * @param key - File key/path
     * @returns Promise with delete result
     */
    delete(key: string): Promise<StorageDeleteResult>;

    /**
     * Check if a file exists in the storage backend
     * @param key - File key/path
     * @returns Promise with existence result
     */
    exists(key: string): Promise<StorageExistsResult>;

    /**
     * Generate a public URL for accessing the file
     * @param key - File key/path
     * @param options - URL generation options
     * @returns Promise with URL result
     */
    getUrl(
        key: string,
        options?: {
            expiresIn?: number; // seconds
            signed?: boolean;
            download?: boolean;
        }
    ): Promise<StorageUrlResult>;

    /**
     * Get capabilities of the storage provider
     * @returns Storage capabilities
     */
    getCapabilities(): StorageCapabilities;

    /**
     * Check the health of the storage backend
     * @returns Promise with health result
     */
    checkHealth(): Promise<StorageHealthResult>;

    /**
     * Generate a unique key for a file
     * @param file - File object
     * @param options - Key generation options
     * @returns Generated key
     */
    generateKey(
        file: MulterFile | { originalname: string; mimetype: string },
        options?: {
            prefix?: string;
            preserveOriginalName?: boolean;
        }
    ): string;

    /**
     * Move a file from one key to another
     * @param fromKey - Source key
     * @param toKey - Destination key
     * @returns Promise with operation result
     */
    move(fromKey: string, toKey: string): Promise<{ success: boolean; error?: string }>;

    /**
     * Copy a file from one key to another
     * @param fromKey - Source key
     * @param toKey - Destination key
     * @returns Promise with operation result
     */
    copy(fromKey: string, toKey: string): Promise<{ success: boolean; error?: string }>;

    /**
     * List files in the storage backend
     * @param prefix - Optional prefix to filter files
     * @param options - List options
     * @returns Promise with list of files
     */
    list(
        prefix?: string,
        options?: {
            maxKeys?: number;
            continuationToken?: string;
        }
    ): Promise<{
        files: Array<{
            key: string;
            size: number;
            lastModified: Date;
            mimeType?: string;
        }>;
        continuationToken?: string;
        truncated: boolean;
    }>;

    /**
     * Get file metadata
     * @param key - File key/path
     * @returns Promise with file metadata
     */
    getMetadata(key: string): Promise<{
        size: number;
        mimeType: string;
        lastModified: Date;
        etag?: string;
        customMetadata?: Record<string, any>;
    } | null>;

    /**
     * Update file metadata
     * @param key - File key/path
     * @param metadata - New metadata
     * @returns Promise with operation result
     */
    updateMetadata(
        key: string,
        metadata: Record<string, any>
    ): Promise<{ success: boolean; error?: string }>;
}