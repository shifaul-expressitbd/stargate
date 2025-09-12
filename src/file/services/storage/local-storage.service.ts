/**
 * Local Storage Service
 * Implements local file system storage using the storage service interface
 */

import {
    Injectable,
    InternalServerErrorException,
    NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { MulterFile } from '../../interfaces/file-options.interface';
import type { LocalStorageOptions } from '../../interfaces/storage-options.interface';
import {
    StorageCapabilities,
    StorageDeleteResult,
    StorageDownloadResult,
    StorageExistsResult,
    StorageProvider,
    StorageUploadResult,
    StorageUrlResult,
} from '../../interfaces/storage.interface';
import { AbstractStorageService } from '../abstract-storage.service';

/**
 * Local storage service implementation
 * Handles file storage on the local file system
 */
@Injectable()
export class LocalStorageService extends AbstractStorageService {
    private readonly fileConfig: LocalStorageOptions;

    constructor(
        options: LocalStorageOptions,
        configService: ConfigService
    ) {
        super(StorageProvider.LOCAL, options, configService);
        this.fileConfig = options;
    }

    /**
     * Upload a file to local storage
     */
    async upload(
        file: MulterFile | Buffer,
        key?: string,
        options?: {
            mimeType?: string;
            metadata?: Record<string, any>;
            permissions?: string;
            expiresAt?: Date;
        }
    ): Promise<StorageUploadResult> {
        try {
            const fileKey = key || this.generateFileKey(file);
            const fullPath = this.getFullPath(fileKey);

            // Ensure directory exists
            await this.ensureDirectoryExists(path.dirname(fullPath));

            // Write file to disk
            if (Buffer.isBuffer(file)) {
                await fs.promises.writeFile(fullPath, file);
            } else {
                await this.moveFile(file.path, fullPath);
            }

            const stats = await fs.promises.stat(fullPath);
            const mimeType = options?.mimeType || this.getMimeType(fileKey);

            return {
                fileId: crypto.randomUUID(),
                key: fileKey,
                url: this.generateLocalUrl(fileKey),
                metadata: {
                    size: stats.size,
                    mimeType,
                    filename: this.extractFilename(fileKey),
                    uploadedAt: new Date(),
                },
                success: true,
            };
        } catch (error) {
            this.logger.error(`Failed to upload file: ${error.message}`, error.stack);
            return {
                fileId: '',
                key: '',
                url: '',
                metadata: {
                    size: 0,
                    mimeType: '',
                    filename: '',
                    uploadedAt: new Date(),
                },
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Download a file from local storage
     */
    async download(key: string): Promise<StorageDownloadResult> {
        try {
            const fullPath = this.getFullPath(key);

            if (!await this.fileExists(fullPath)) {
                throw new NotFoundException('File not found');
            }

            const stats = await fs.promises.stat(fullPath);
            const stream = fs.createReadStream(fullPath, {
                highWaterMark: 64 * 1024, // 64KB chunks
            });

            return {
                stream,
                metadata: {
                    size: stats.size,
                    mimeType: this.getMimeType(key),
                    lastModified: stats.mtime,
                },
                success: true,
            };
        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Failed to download file ${key}: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Delete a file from local storage
     */
    async delete(key: string): Promise<StorageDeleteResult> {
        try {
            const fullPath = this.getFullPath(key);

            if (!await this.fileExists(fullPath)) {
                return {
                    success: false,
                    error: 'File not found',
                };
            }

            await fs.promises.unlink(fullPath);

            // Try to cleanup empty directories
            await this.cleanupEmptyDirectories(path.dirname(fullPath));

            this.logger.log(`File deleted successfully: ${key}`);
            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to delete file ${key}: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Check if a file exists in local storage
     */
    async exists(key: string): Promise<StorageExistsResult> {
        try {
            const fullPath = this.getFullPath(key);
            const fileExists = await this.fileExists(fullPath);

            if (!fileExists) {
                return {
                    exists: false,
                };
            }

            const stats = await fs.promises.stat(fullPath);
            return {
                exists: true,
                metadata: {
                    size: stats.size,
                    mimeType: this.getMimeType(key),
                    lastModified: stats.mtime,
                },
            };
        } catch (error) {
            this.logger.error(`Failed to check existence of file ${key}: ${error.message}`, error.stack);
            return {
                exists: false,
            };
        }
    }

    /**
     * Generate a URL for accessing the file
     */
    async getUrl(
        key: string,
        options?: {
            expiresIn?: number;
            signed?: boolean;
            download?: boolean;
        }
    ): Promise<StorageUrlResult> {
        try {
            // Local storage doesn't support signed URLs or expiration
            // Just return the basic URL
            return {
                url: this.generateLocalUrl(key),
                success: true,
            };
        } catch (error) {
            this.logger.error(`Failed to generate URL for file ${key}: ${error.message}`, error.stack);
            return {
                url: '',
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Get capabilities of local storage
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
     * Copy a file within local storage
     */
    async copy(fromKey: string, toKey: string): Promise<{ success: boolean; error?: string }> {
        try {
            const fromPath = this.getFullPath(fromKey);
            const toPath = this.getFullPath(toKey);

            if (!await this.fileExists(fromPath)) {
                return {
                    success: false,
                    error: 'Source file not found',
                };
            }

            // Ensure destination directory exists
            await this.ensureDirectoryExists(path.dirname(toPath));

            await fs.promises.copyFile(fromPath, toPath);

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to copy file from ${fromKey} to ${toKey}: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * List files in local storage
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
        const basePath = this.getFullPath(prefix || '');
        const files: Array<{
            key: string;
            size: number;
            lastModified: Date;
            mimeType?: string;
        }> = [];

        try {
            const items = await fs.promises.readdir(basePath, { withFileTypes: true });

            for (const item of items) {
                if (item.isFile()) {
                    const filePath = path.join(basePath, item.name);
                    const stats = await fs.promises.stat(filePath);
                    const key = prefix ? `${prefix}/${item.name}` : item.name;

                    files.push({
                        key,
                        size: stats.size,
                        lastModified: stats.mtime,
                        mimeType: this.getMimeType(item.name),
                    });
                }
            }

            return {
                files: files.slice(0, options?.maxKeys || files.length),
                truncated: files.length > (options?.maxKeys || files.length),
            };
        } catch (error) {
            this.logger.error(`Failed to list files: ${error.message}`, error.stack);
            return {
                files: [],
                truncated: false,
            };
        }
    }

    /**
     * Get file metadata
     */
    async getMetadata(key: string): Promise<{
        size: number;
        mimeType: string;
        lastModified: Date;
        etag?: string;
        customMetadata?: Record<string, any>;
    } | null> {
        try {
            const fullPath = this.getFullPath(key);

            if (!await this.fileExists(fullPath)) {
                return null;
            }

            const stats = await fs.promises.stat(fullPath);

            return {
                size: stats.size,
                mimeType: this.getMimeType(key),
                lastModified: stats.mtime,
                etag: `"${stats.mtime.getTime()}-${stats.size}"`,
            };
        } catch (error) {
            this.logger.error(`Failed to get metadata for file ${key}: ${error.message}`, error.stack);
            return null;
        }
    }

    /**
     * Perform health check for local storage
     */
    protected async performHealthCheck(): Promise<boolean> {
        try {
            // Check if base directory exists and is writable
            const baseDir = this.fileConfig.baseDir;

            await fs.promises.access(baseDir, fs.constants.W_OK);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generate a file key for local storage
     */
    private generateFileKey(file: MulterFile | Buffer): string {
        if (Buffer.isBuffer(file)) {
            // For buffer uploads, generate a generic key
            const timestamp = Date.now();
            const random = crypto.randomBytes(4).toString('hex');
            return `buffer_${timestamp}_${random}`;
        }

        // Use the existing logic for MulterFile
        return this.generateKey(file, {
            preserveOriginalName: false,
        });
    }


    /**
     * Get full path for a file key
     */
    private getFullPath(key: string): string {
        return path.join(this.fileConfig.baseDir, key);
    }

    /**
     * Generate local URL for a file
     */
    private generateLocalUrl(key: string): string {
        const baseUrl = this.options.baseUrl || 'http://localhost:3000';
        // For local storage, serve files through our public file controller
        return `${baseUrl}/files/${key}`;
    }

    /**
     * Extract filename from key
     */
    private extractFilename(key: string): string {
        return path.basename(key);
    }

    /**
     * Check if file exists
     */
    private async fileExists(filePath: string): Promise<boolean> {
        try {
            await fs.promises.access(filePath, fs.constants.F_OK);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Ensure directory exists
     */
    private async ensureDirectoryExists(directory: string): Promise<void> {
        try {
            await fs.promises.mkdir(directory, { recursive: true });
        } catch (error) {
            if (error.code !== 'EEXIST') {
                throw new InternalServerErrorException(`Failed to create directory: ${directory}`);
            }
        }
    }

    /**
     * Move file from source to destination
     */
    private async moveFile(sourcePath: string, destPath: string): Promise<void> {
        try {
            await fs.promises.rename(sourcePath, destPath);
        } catch (error) {
            // If rename fails (e.g., cross-device), try copy + delete
            try {
                await fs.promises.copyFile(sourcePath, destPath);
                await fs.promises.unlink(sourcePath);
            } catch (copyError) {
                throw new InternalServerErrorException('Failed to move file');
            }
        }
    }

    /**
     * Clean up empty directories recursively
     */
    private async cleanupEmptyDirectories(directory: string): Promise<void> {
        try {
            const items = await fs.promises.readdir(directory);

            if (items.length === 0) {
                await fs.promises.rmdir(directory);

                // Recursively check parent directory
                const parentDir = path.dirname(directory);
                if (parentDir !== directory) { // Avoid infinite loop at root
                    await this.cleanupEmptyDirectories(parentDir);
                }
            }
        } catch (error) {
            // Ignore errors during cleanup
            this.logger.debug(`Failed to cleanup directory ${directory}: ${error.message}`);
        }
    }
}