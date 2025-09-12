/**
 * Google Cloud Storage Service
 * Implements Google Cloud Storage for enterprise-grade cloud storage
 */

// import {
//     Bucket,
//     Storage as GoogleCloudStorage
// } from '@google-cloud/storage';
import {
    Injectable,
    NotFoundException
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { MulterFile } from '../../interfaces/file-options.interface';
import type { GoogleCloudStorageOptions } from '../../interfaces/storage-options.interface';
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
 * Google Cloud Storage service implementation
 * Handles file storage using Google Cloud Storage for enterprise-grade cloud storage
 *
 * NOTE: This service requires the @google-cloud/storage package to be installed:
 * npm install @google-cloud/storage
 */
@Injectable()
export class GoogleCloudStorageService extends AbstractStorageService {
    private readonly gcsClient: any; // GoogleCloudStorage
    private readonly gcsConfig: GoogleCloudStorageOptions;
    private readonly bucket: any; // Bucket

    constructor(
        options: GoogleCloudStorageOptions,
        configService: ConfigService
    ) {
        super(StorageProvider.GOOGLE_CLOUD, options, configService);
        this.gcsConfig = options;

        // Check if @google-cloud/storage is available
        try {
            const gcsModule = require('@google-cloud/storage');
            const GoogleCloudStorage = gcsModule.Storage;

            this.gcsClient = new GoogleCloudStorage({
                projectId: this.gcsConfig.projectId,
                keyFilename: this.gcsConfig.keyFilename,
                credentials: this.gcsConfig.credentials,
            });

            this.bucket = this.gcsClient.bucket(this.gcsConfig.bucket);
        } catch (error) {
            this.logger.warn('Google Cloud Storage package not found. Install with: npm install @google-cloud/storage');
            throw new Error('Google Cloud Storage package not installed. Please run: npm install @google-cloud/storage');
        }
    }

    /**
     * Upload a file to Google Cloud Storage
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

            let buffer: Buffer;
            let contentType: string;
            let size: number;

            if (Buffer.isBuffer(file)) {
                buffer = file;
                contentType = options?.mimeType || 'application/octet-stream';
                size = file.length;
            } else {
                buffer = require('fs').readFileSync(file.path);
                contentType = options?.mimeType || file.mimetype;
                size = file.size;
            }

            const gcsFile = (this.bucket as any).file(fileKey);
            const stream = (gcsFile as any).createWriteStream({
                metadata: {
                    contentType,
                    metadata: options?.metadata,
                },
                public: options?.permissions === 'public-read',
            });

            return new Promise((resolve, reject) => {
                stream.on('error', (error) => {
                    this.logger.error(`Failed to upload file to GCS: ${error.message}`, error.stack);
                    resolve({
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
                    });
                });

                stream.on('finish', async () => {
                    try {
                        const [metadata] = await gcsFile.getMetadata();

                        const url = this.gcsConfig.publicUrl
                            ? `${this.gcsConfig.publicUrl}/${fileKey}`
                            : await this.generateSignedUrl(fileKey, 3600); // 1 hour default

                        resolve({
                            fileId: crypto.randomUUID(),
                            key: fileKey,
                            url,
                            metadata: {
                                size,
                                mimeType: contentType,
                                filename: this.extractFilename(fileKey),
                                uploadedAt: new Date(),
                            },
                            providerMetadata: {
                                etag: metadata.etag,
                                generation: metadata.generation,
                                metageneration: metadata.metageneration,
                            },
                            success: true,
                        });
                    } catch (error) {
                        reject(error);
                    }
                });

                stream.end(buffer);
            });
        } catch (error) {
            this.logger.error(`Failed to upload file to GCS: ${error.message}`, error.stack);
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
     * Download a file from Google Cloud Storage
     */
    async download(key: string): Promise<StorageDownloadResult> {
        try {
            const gcsFile = (this.bucket as any).file(key);
            const [exists] = await gcsFile.exists();
            if (!exists) {
                throw new NotFoundException('File not found');
            }

            const stream = gcsFile.createReadStream();
            const [metadata] = await gcsFile.getMetadata();

            return {
                stream,
                metadata: {
                    size: parseInt(metadata.size || '0'),
                    mimeType: metadata.contentType || 'application/octet-stream',
                    lastModified: new Date(metadata.updated || Date.now()),
                },
                success: true,
            };
        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Failed to download file ${key} from GCS: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Delete a file from Google Cloud Storage
     */
    async delete(key: string): Promise<StorageDeleteResult> {
        try {
            const gcsFile = (this.bucket as any).file(key);
            await gcsFile.delete();

            this.logger.log(`File deleted successfully: ${key}`);
            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to delete file ${key} from GCS: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Check if a file exists in Google Cloud Storage
     */
    async exists(key: string): Promise<StorageExistsResult> {
        try {
            const gcsFile = (this.bucket as any).file(key);
            const [exists] = await gcsFile.exists();

            if (exists) {
                const [metadata] = await gcsFile.getMetadata();
                return {
                    exists: true,
                    metadata: {
                        size: parseInt(metadata.size || '0'),
                        mimeType: metadata.contentType || 'application/octet-stream',
                        lastModified: new Date(metadata.updated || Date.now()),
                    },
                };
            }

            return { exists: false };
        } catch (error) {
            this.logger.error(`Failed to check existence of file ${key} in GCS: ${error.message}`, error.stack);
            return { exists: false };
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
            const gcsFile = (this.bucket as any).file(key);

            if (this.gcsConfig.publicUrl && !options?.signed) {
                // Return public URL
                const url = `${this.gcsConfig.publicUrl}/${key}`;
                return {
                    url,
                    success: true,
                };
            }

            // Generate signed URL
            const expiresIn = options?.expiresIn || 3600; // 1 hour default
            const expires = Date.now() + expiresIn * 1000;

            const [signedUrl] = await gcsFile.getSignedUrl({
                action: 'read',
                expires,
                responseDisposition: options?.download ? `attachment; filename="${this.extractFilename(key)}"` : undefined,
            });

            return {
                url: signedUrl,
                success: true,
                expiresAt: new Date(expires),
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
     * Get capabilities of Google Cloud Storage
     */
    getCapabilities(): StorageCapabilities {
        return {
            resumableUpload: true,
            signedUrls: true,
            cdnIntegration: true,
            versioning: this.gcsConfig.versioning || false,
            customMetadata: true,
            maxFileSize: 5 * 1024 * 1024 * 1024 * 1024, // 5TB
            storageClasses: [
                'STANDARD',
                'NEARLINE',
                'COLDLINE',
                'ARCHIVE',
            ],
            features: {
                lifecycleManagement: true,
                crossRegionReplication: true,
                encryptionAtRest: true,
            },
        };
    }

    /**
     * Copy a file within Google Cloud Storage
     */
    async copy(fromKey: string, toKey: string): Promise<{ success: boolean; error?: string }> {
        try {
            const srcFile = (this.bucket as any).file(fromKey);
            const destFile = (this.bucket as any).file(toKey);

            await srcFile.copy(destFile);

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to copy file from ${fromKey} to ${toKey} in GCS: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * List files in Google Cloud Storage
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
        try {
            const [files, nextQuery] = await this.bucket.getFiles({
                prefix,
                maxResults: options?.maxKeys || 1000,
                autoPaginate: false,
                pageToken: options?.continuationToken,
            });

            const fileList = files.map(file => ({
                key: file.name,
                size: parseInt(file.metadata?.size || '0'),
                lastModified: new Date(file.metadata?.updated || Date.now()),
                mimeType: file.metadata?.contentType,
            }));

            return {
                files: fileList,
                continuationToken: nextQuery?.pageToken,
                truncated: !!nextQuery?.pageToken,
            };
        } catch (error) {
            this.logger.error(`Failed to list files in GCS: ${error.message}`, error.stack);
            return {
                files: [],
                truncated: false,
            };
        }
    }

    /**
     * Get file metadata from Google Cloud Storage
     */
    async getMetadata(key: string): Promise<{
        size: number;
        mimeType: string;
        lastModified: Date;
        etag?: string;
        customMetadata?: Record<string, any>;
    } | null> {
        try {
            const gcsFile = (this.bucket as any).file(key);
            const [metadata] = await gcsFile.getMetadata();

            return {
                size: parseInt(metadata.size || '0'),
                mimeType: metadata.contentType || 'application/octet-stream',
                lastModified: new Date(metadata.updated || Date.now()),
                etag: metadata.etag,
                customMetadata: metadata.metadata,
            };
        } catch (error) {
            this.logger.error(`Failed to get metadata for file ${key} from GCS: ${error.message}`, error.stack);
            return null;
        }
    }

    /**
     * Update file metadata in Google Cloud Storage
     */
    async updateMetadata(
        key: string,
        metadata: Record<string, any>
    ): Promise<{ success: boolean; error?: string }> {
        try {
            const gcsFile = (this.bucket as any).file(key);
            await gcsFile.setMetadata({
                metadata,
            });

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to update metadata for file ${key} in GCS: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Perform health check for Google Cloud Storage
     */
    protected async performHealthCheck(): Promise<boolean> {
        try {
            // Try to list files to verify connection
            const [files] = await this.bucket.getFiles({ maxResults: 1 });
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generate a file key for Google Cloud Storage
     */
    private generateFileKey(file: MulterFile | Buffer): string {
        if (Buffer.isBuffer(file)) {
            const timestamp = Date.now();
            const random = crypto.randomBytes(4).toString('hex');
            return `buffer_${timestamp}_${random}`;
        }

        return this.generateKey(file, {
            preserveOriginalName: false,
        });
    }

    /**
     * Extract filename from key
     */
    private extractFilename(key: string): string {
        return key.split('/').pop() || key;
    }

    /**
     * Generate a signed URL for Google Cloud Storage
     */
    private async generateSignedUrl(key: string, expiresIn: number): Promise<string> {
        const gcsFile = (this.bucket as any).file(key);
        const expires = Date.now() + expiresIn * 1000;

        const [signedUrl] = await gcsFile.getSignedUrl({
            action: 'read',
            expires,
        });

        return signedUrl;
    }
}