/**
 * Cloudflare R2 Storage Service
 * Implements Cloudflare R2 storage using AWS SDK v3 with S3-compatible API
 */

import {
    CopyObjectCommand,
    DeleteObjectCommand,
    GetObjectCommand,
    HeadObjectCommand,
    ListObjectsV2Command,
    PutObjectCommand,
    S3Client
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import {
    Inject,
    Injectable,
    NotFoundException
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { MulterFile } from '../../interfaces/file-options.interface';
import type { R2StorageOptions } from '../../interfaces/storage-options.interface';
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
 * Cloudflare R2 storage service implementation
 * Uses AWS SDK v3 with Cloudflare R2's S3-compatible API
 */
@Injectable()
export class CloudflareR2StorageService extends AbstractStorageService {
    private readonly s3Client: S3Client;
    private readonly r2Config: R2StorageOptions;

    constructor(
        @Inject('R2_STORAGE_OPTIONS') options: R2StorageOptions,
        configService: ConfigService
    ) {
        super(StorageProvider.CLOUDFLARE_R2, options, configService);
        this.r2Config = options;

        // Initialize S3 client with R2 configuration
        this.s3Client = new S3Client({
            region: 'auto', // R2 uses 'auto' region
            credentials: {
                accessKeyId: this.r2Config.accessKeyId,
                secretAccessKey: this.r2Config.secretAccessKey,
            },
            endpoint: this.r2Config.endpoint,
            forcePathStyle: true, // R2 requires path-style URLs
        });
    }

    /**
     * Upload a file to R2
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

            let body: Buffer;
            let contentType: string;
            let contentLength: number;

            if (Buffer.isBuffer(file)) {
                body = file;
                contentType = options?.mimeType || 'application/octet-stream';
                contentLength = file.length;
            } else {
                body = require('fs').readFileSync(file.path);
                contentType = options?.mimeType || file.mimetype;
                contentLength = file.size;
            }

            const uploadParams = {
                Bucket: this.r2Config.bucket,
                Key: fileKey,
                Body: body,
                ContentType: contentType,
                ContentLength: contentLength,
                Metadata: options?.metadata,
            };

            const command = new PutObjectCommand(uploadParams);
            const result = await this.s3Client.send(command);

            const url = this.r2Config.publicUrl
                ? `${this.r2Config.publicUrl}/${fileKey}`
                : await this.generatePresignedUrl(fileKey, 3600); // 1 hour default

            return {
                fileId: crypto.randomUUID(),
                key: fileKey,
                url,
                metadata: {
                    size: contentLength,
                    mimeType: contentType,
                    filename: this.extractFilename(fileKey),
                    uploadedAt: new Date(),
                },
                providerMetadata: {
                    etag: result.ETag,
                    versionId: result.VersionId,
                },
                success: true,
            };
        } catch (error) {
            this.logger.error(`Failed to upload file to R2: ${error.message}`, error.stack);
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
     * Download a file from R2
     */
    async download(key: string): Promise<StorageDownloadResult> {
        try {
            const command = new GetObjectCommand({
                Bucket: this.r2Config.bucket,
                Key: key,
            });

            const response = await this.s3Client.send(command);

            return {
                stream: response.Body as NodeJS.ReadableStream,
                metadata: {
                    size: response.ContentLength || 0,
                    mimeType: response.ContentType || 'application/octet-stream',
                    lastModified: response.LastModified || new Date(),
                },
                success: true,
            };
        } catch (error) {
            if (error.name === 'NoSuchKey') {
                throw new NotFoundException('File not found');
            }
            this.logger.error(`Failed to download file ${key} from R2: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Delete a file from R2
     */
    async delete(key: string): Promise<StorageDeleteResult> {
        try {
            const command = new DeleteObjectCommand({
                Bucket: this.r2Config.bucket,
                Key: key,
            });

            await this.s3Client.send(command);

            this.logger.log(`File deleted successfully: ${key}`);
            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to delete file ${key} from R2: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Check if a file exists in R2
     */
    async exists(key: string): Promise<StorageExistsResult> {
        try {
            const command = new HeadObjectCommand({
                Bucket: this.r2Config.bucket,
                Key: key,
            });

            const response = await this.s3Client.send(command);

            return {
                exists: true,
                metadata: {
                    size: response.ContentLength || 0,
                    mimeType: response.ContentType || 'application/octet-stream',
                    lastModified: response.LastModified || new Date(),
                },
            };
        } catch (error) {
            if (error.name === 'NotFound') {
                return { exists: false };
            }
            this.logger.error(`Failed to check existence of file ${key} in R2: ${error.message}`, error.stack);
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
            if (this.r2Config.publicUrl && !options?.signed) {
                // Return public URL
                const url = `${this.r2Config.publicUrl}/${key}`;
                return {
                    url,
                    success: true,
                };
            }

            // Generate signed URL
            const expiresIn = options?.expiresIn || 3600; // 1 hour default
            const signedUrl = await this.generatePresignedUrl(key, expiresIn);

            return {
                url: signedUrl,
                success: true,
                expiresAt: new Date(Date.now() + expiresIn * 1000),
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
     * Get capabilities of R2 storage
     */
    getCapabilities(): StorageCapabilities {
        return {
            resumableUpload: true,
            signedUrls: true,
            cdnIntegration: false, // R2 doesn't have built-in CDN
            versioning: false, // R2 doesn't support versioning yet
            customMetadata: true,
            maxFileSize: 5 * 1024 * 1024 * 1024 * 1024, // 5TB, same as S3
            storageClasses: [
                'STANDARD', // R2 only has standard storage class
            ],
            features: {
                lifecycleManagement: false,
                crossRegionReplication: false,
                encryptionAtRest: true,
                globalReplication: true, // R2 has global replication
            },
        };
    }

    /**
     * Copy a file within R2
     */
    async copy(fromKey: string, toKey: string): Promise<{ success: boolean; error?: string }> {
        try {
            const command = new CopyObjectCommand({
                Bucket: this.r2Config.bucket,
                CopySource: `${this.r2Config.bucket}/${fromKey}`,
                Key: toKey,
            });

            await this.s3Client.send(command);

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to copy file from ${fromKey} to ${toKey} in R2: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * List files in R2
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
            const command = new ListObjectsV2Command({
                Bucket: this.r2Config.bucket,
                Prefix: prefix,
                MaxKeys: options?.maxKeys || 1000,
                ContinuationToken: options?.continuationToken,
            });

            const response = await this.s3Client.send(command);

            const files = (response.Contents || []).map(object => ({
                key: object.Key || '',
                size: object.Size || 0,
                lastModified: object.LastModified || new Date(),
                mimeType: undefined, // Would need HeadObject to get MIME type
            }));

            return {
                files,
                continuationToken: response.NextContinuationToken,
                truncated: response.IsTruncated || false,
            };
        } catch (error) {
            this.logger.error(`Failed to list files in R2: ${error.message}`, error.stack);
            return {
                files: [],
                truncated: false,
            };
        }
    }

    /**
     * Get file metadata from R2
     */
    async getMetadata(key: string): Promise<{
        size: number;
        mimeType: string;
        lastModified: Date;
        etag?: string;
        customMetadata?: Record<string, any>;
    } | null> {
        try {
            const command = new HeadObjectCommand({
                Bucket: this.r2Config.bucket,
                Key: key,
            });

            const response = await this.s3Client.send(command);

            return {
                size: response.ContentLength || 0,
                mimeType: response.ContentType || 'application/octet-stream',
                lastModified: response.LastModified || new Date(),
                etag: response.ETag,
                customMetadata: response.Metadata,
            };
        } catch (error) {
            if (error.name === 'NotFound') {
                return null;
            }
            this.logger.error(`Failed to get metadata for file ${key} from R2: ${error.message}`, error.stack);
            return null;
        }
    }

    /**
     * Update file metadata in R2
     */
    async updateMetadata(
        key: string,
        metadata: Record<string, any>
    ): Promise<{ success: boolean; error?: string }> {
        try {
            // R2 doesn't support updating metadata directly
            // We need to copy the object with new metadata
            const command = new CopyObjectCommand({
                Bucket: this.r2Config.bucket,
                CopySource: `${this.r2Config.bucket}/${key}`,
                Key: key,
                Metadata: metadata,
                MetadataDirective: 'REPLACE',
            });

            await this.s3Client.send(command);

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to update metadata for file ${key} in R2: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Perform health check for R2
     */
    protected async performHealthCheck(): Promise<boolean> {
        try {
            // Try to list objects to verify connection
            const command = new ListObjectsV2Command({
                Bucket: this.r2Config.bucket,
                MaxKeys: 1,
            });

            await this.s3Client.send(command);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generate a file key for R2
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
     * Generate a presigned URL for R2
     */
    private async generatePresignedUrl(key: string, expiresIn: number): Promise<string> {
        const command = new GetObjectCommand({
            Bucket: this.r2Config.bucket,
            Key: key,
        });

        return await getSignedUrl(this.s3Client, command, { expiresIn });
    }
}