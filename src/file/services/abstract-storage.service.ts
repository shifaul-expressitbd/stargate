/**
 * Abstract Storage Service Base Class
 * Provides common functionality for all storage service implementations
 */

import {
    BadRequestException,
    InternalServerErrorException,
    Logger,
    NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as path from 'path';
import { MulterFile } from '../interfaces/file-options.interface';
import { IStorageService } from '../interfaces/istorage-service.interface';
import { AllStorageOptions } from '../interfaces/storage-options.interface';
import {
    StorageCapabilities,
    StorageDeleteResult,
    StorageDownloadResult,
    StorageExistsResult,
    StorageHealthResult,
    StorageProvider,
    StorageUploadResult,
    StorageUrlResult,
} from '../interfaces/storage.interface';

/**
 * Abstract base class for all storage services
 * Implements common functionality and provides a foundation for concrete implementations
 */
export abstract class AbstractStorageService implements IStorageService {
    protected readonly logger: Logger;
    protected readonly configService: ConfigService;
    protected readonly provider: StorageProvider;
    protected readonly options: AllStorageOptions;

    constructor(
        provider: StorageProvider,
        options: AllStorageOptions,
        configService: ConfigService
    ) {
        this.provider = provider;
        this.options = options;
        this.configService = configService;
        this.logger = new Logger(`${AbstractStorageService.name}:${provider}`);
    }

    /**
     * Abstract method for uploading a file
     * Must be implemented by concrete storage services
     */
    abstract upload(
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
     * Abstract method for downloading a file
     * Must be implemented by concrete storage services
     */
    abstract download(key: string): Promise<StorageDownloadResult>;

    /**
     * Abstract method for deleting a file
     * Must be implemented by concrete storage services
     */
    abstract delete(key: string): Promise<StorageDeleteResult>;

    /**
     * Abstract method for checking file existence
     * Must be implemented by concrete storage services
     */
    abstract exists(key: string): Promise<StorageExistsResult>;

    /**
     * Abstract method for generating file URLs
     * Must be implemented by concrete storage services
     */
    abstract getUrl(
        key: string,
        options?: {
            expiresIn?: number;
            signed?: boolean;
            download?: boolean;
        }
    ): Promise<StorageUrlResult>;

    /**
     * Get capabilities of the storage provider
     * Can be overridden by concrete implementations
     */
    getCapabilities(): StorageCapabilities {
        return {
            resumableUpload: false,
            signedUrls: false,
            cdnIntegration: false,
            versioning: false,
            customMetadata: false,
        };
    }

    /**
     * Default health check implementation
     * Can be overridden by concrete implementations
     */
    async checkHealth(): Promise<StorageHealthResult> {
        const startTime = Date.now();

        try {
            // Basic connectivity test - can be overridden
            const result = await this.performHealthCheck();

            return {
                healthy: result,
                responseTime: Date.now() - startTime,
            };
        } catch (error) {
            return {
                healthy: false,
                responseTime: Date.now() - startTime,
                error: error.message,
            };
        }
    }

    /**
     * Default key generation implementation
     * Can be overridden by concrete implementations
     */
    generateKey(
        file: MulterFile | { originalname: string; mimetype: string },
        options: {
            prefix?: string;
            preserveOriginalName?: boolean;
        } = {}
    ): string {
        const { prefix = '', preserveOriginalName = false } = options;

        let filename: string;

        if (preserveOriginalName && file.originalname) {
            filename = file.originalname;
        } else {
            const ext = path.extname(file.originalname || 'file');
            const baseName = path.basename(file.originalname || 'file', ext);
            const timestamp = Date.now();
            const random = crypto.randomBytes(4).toString('hex');

            filename = `${baseName}_${timestamp}_${random}${ext}`;
        }

        return prefix ? `${prefix}/${filename}` : filename;
    }

    /**
     * Default move implementation using copy and delete
     * Can be overridden by concrete implementations for optimization
     */
    async move(fromKey: string, toKey: string): Promise<{ success: boolean; error?: string }> {
        try {
            const copyResult = await this.copy(fromKey, toKey);
            if (!copyResult.success) {
                return copyResult;
            }

            const deleteResult = await this.delete(fromKey);
            if (!deleteResult.success) {
                // Cleanup: try to delete the copied file if delete of original failed
                await this.delete(toKey);
                return {
                    success: false,
                    error: `Failed to delete original file after copy: ${deleteResult.error}`,
                };
            }

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to move file from ${fromKey} to ${toKey}: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Abstract method for copying files
     * Must be implemented by concrete storage services
     */
    abstract copy(fromKey: string, toKey: string): Promise<{ success: boolean; error?: string }>;

    /**
     * Default list implementation
     * Can be overridden by concrete implementations
     */
    async list(
        prefix?: string,
        options?: { maxKeys?: number; continuationToken?: string }
    ): Promise<{
        files: Array<{
            key: string;
            size: number;
            lastModified: Date;
            mimeType?: string;
        }>;
        continuationToken?: string;
        truncated: boolean;
    }> {
        // Default implementation returns empty list
        // Concrete implementations should override this
        return {
            files: [],
            truncated: false,
        };
    }

    /**
     * Default metadata retrieval
     * Can be overridden by concrete implementations
     */
    async getMetadata(key: string): Promise<{
        size: number;
        mimeType: string;
        lastModified: Date;
        etag?: string;
        customMetadata?: Record<string, any>;
    } | null> {
        // Default implementation returns null
        // Concrete implementations should override this if supported
        return null;
    }

    /**
     * Default metadata update
     * Can be overridden by concrete implementations
     */
    async updateMetadata(
        key: string,
        metadata: Record<string, any>
    ): Promise<{ success: boolean; error?: string }> {
        // Default implementation does nothing
        // Concrete implementations should override this if supported
        return {
            success: false,
            error: 'Metadata updates not supported by this storage provider',
        };
    }

    /**
     * Perform health check - to be implemented by concrete services
     */
    protected abstract performHealthCheck(): Promise<boolean>;

    /**
     * Common error handling utility
     */
    protected handleError(error: any, operation: string): never {
        this.logger.error(`Storage operation '${operation}' failed: ${error.message}`, error.stack);

        if (error instanceof NotFoundException) {
            throw error;
        }

        if (error.code === 'ENOENT' || error.message?.includes('not found')) {
            throw new NotFoundException(`File not found during ${operation}`);
        }

        if (error.code === 'EACCES' || error.message?.includes('permission')) {
            throw new BadRequestException(`Permission denied during ${operation}`);
        }

        throw new InternalServerErrorException(`Storage operation '${operation}' failed: ${error.message}`);
    }

    /**
     * Retry utility with exponential backoff
     */
    protected async withRetry<T>(
        operation: () => Promise<T>,
        operationName: string,
        maxAttempts: number = 3,
        baseDelay: number = 1000
    ): Promise<T> {
        let lastError: any;

        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return await operation();
            } catch (error) {
                lastError = error;

                if (attempt === maxAttempts) {
                    break;
                }

                const delay = baseDelay * Math.pow(2, attempt - 1);
                this.logger.warn(
                    `${operationName} failed (attempt ${attempt}/${maxAttempts}), retrying in ${delay}ms: ${error.message}`
                );

                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }

        throw lastError;
    }

    /**
     * Validate file type and size
     */
    protected validateFile(
        file: MulterFile | Buffer,
        options?: {
            maxSize?: number;
            allowedTypes?: string[];
        }
    ): void {
        if (!options) return;

        const { maxSize, allowedTypes } = options;

        // Size validation
        if (maxSize && Buffer.isBuffer(file) && file.length > maxSize) {
            throw new BadRequestException(`File size exceeds maximum allowed size of ${maxSize} bytes`);
        }

        if (maxSize && !Buffer.isBuffer(file) && file.size > maxSize) {
            throw new BadRequestException(`File size exceeds maximum allowed size of ${maxSize} bytes`);
        }

        // Type validation
        if (allowedTypes && !Buffer.isBuffer(file) && file.mimetype) {
            const isAllowed = allowedTypes.some(type =>
                file.mimetype === type ||
                file.mimetype.startsWith(type.replace('*', ''))
            );

            if (!isAllowed) {
                throw new BadRequestException(
                    `File type ${file.mimetype} is not allowed. Allowed types: ${allowedTypes.join(', ')}`
                );
            }
        }
    }

    /**
     * Generate file ID
     */
    protected generateFileId(): string {
        return crypto.randomUUID();
    }

    /**
     * Get MIME type from file path or buffer
     */
    protected getMimeType(filePath: string): string {
        const ext = path.extname(filePath).toLowerCase();

        const mimeTypes: Record<string, string> = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.pdf': 'application/pdf',
            '.txt': 'text/plain',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.ppt': 'application/vnd.ms-powerpoint',
            '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            '.zip': 'application/zip',
            '.rar': 'application/x-rar-compressed',
            '.7z': 'application/x-7z-compressed',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
        };

        return mimeTypes[ext] || 'application/octet-stream';
    }
}