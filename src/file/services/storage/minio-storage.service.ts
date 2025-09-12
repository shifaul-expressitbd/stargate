/**
 * MinIO Storage Service
 * Implements MinIO storage for S3-compatible private cloud storage
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
    Injectable,
    NotFoundException
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { MulterFile } from '../../interfaces/file-options.interface';
import type { MinIOStorageOptions } from '../../interfaces/storage-options.interface';
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
 * MinIO storage service implementation
 * Handles file storage using MinIO for private S3-compatible storage
 */
@Injectable()
export class MinIOStorageService extends AbstractStorageService {
    private readonly s3Client: S3Client;
    private readonly minioConfig: MinIOStorageOptions;

    constructor(
        options: MinIOStorageOptions,
        configService: ConfigService
    ) {
        super(StorageProvider.MINIO, options, configService);
        this.minioConfig = options;

        this.s3Client = new S3Client({
            region: this.minioConfig.region || 'us-east-1',
            credentials: {
                accessKeyId: this.minioConfig.accessKey,
                secretAccessKey: this.minioConfig.secretKey,
            },
            endpoint: this.minioConfig.endPoint,
            forcePathStyle: true, // MinIO requires path-style URLs
        });
    }

    /**
     * Upload a file to MinIO
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
                Bucket: this.minioConfig.bucket,
                Key: fileKey,
                Body: body,
                ContentType: contentType,
                ContentLength: contentLength,
                Metadata: options?.metadata,
            };

            const command = new PutObjectCommand(uploadParams);
            const result = await this.s3Client.send(command);

            const url = this.minioConfig.publicUrl
                ? `${this.minioConfig.publicUrl}/${fileKey}`
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
            this.logger.error(`Failed to upload file to MinIO: ${error.message}`, error.stack);
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
     * Download a file from MinIO
     */
    async download(key: string): Promise<StorageDownloadResult> {
        try {
            const command = new GetObjectCommand({
                Bucket: this.minioConfig.bucket,
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
            this.logger.error(`Failed to download file ${key} from MinIO: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Delete a file from MinIO
     */
    async delete(key: string): Promise<StorageDeleteResult> {
        try {
            const command = new DeleteObjectCommand({
                Bucket: this.minioConfig.bucket,
                Key: key,
            });

            await this.s3Client.send(command);

            this.logger.log(`File deleted successfully: ${key}`);
            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to delete file ${key} from MinIO: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Check if a file exists in MinIO
     */
    async exists(key: string): Promise<StorageExistsResult> {
        try {
            const command = new HeadObjectCommand({
                Bucket: this.minioConfig.bucket,
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
            this.logger.error(`Failed to check existence of file ${key} in MinIO: ${error.message}`, error.stack);
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
            if (this.minioConfig.publicUrl && !options?.signed) {
                // Return public URL
                const url = `${this.minioConfig.publicUrl}/${key}`;
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
     * Get capabilities of MinIO storage
     */
    getCapabilities(): StorageCapabilities {
        return {
            resumableUpload: true,
            signedUrls: true,
            cdnIntegration: false, // MinIO typically doesn't have built-in CDN
            versioning: true,
            customMetadata: true,
            maxFileSize: 5 * 1024 * 1024 * 1024 * 1024, // 5TB (same as S3)
            storageClasses: [
                'STANDARD',
            ],
            features: {
                lifecycleManagement: true,
                crossRegionReplication: false, // Usually single region
                encryptionAtRest: true,
            },
        };
    }

    /**
     * Copy a file within MinIO
     */
    async copy(fromKey: string, toKey: string): Promise<{ success: boolean; error?: string }> {
        try {
            const command = new CopyObjectCommand({
                Bucket: this.minioConfig.bucket,
                CopySource: `${this.minioConfig.bucket}/${fromKey}`,
                Key: toKey,
            });

            await this.s3Client.send(command);

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to copy file from ${fromKey} to ${toKey} in MinIO: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * List files in MinIO
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
                Bucket: this.minioConfig.bucket,
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
            this.logger.error(`Failed to list files in MinIO: ${error.message}`, error.stack);
            return {
                files: [],
                truncated: false,
            };
        }
    }

    /**
     * Get file metadata from MinIO
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
                Bucket: this.minioConfig.bucket,
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
            this.logger.error(`Failed to get metadata for file ${key} from MinIO: ${error.message}`, error.stack);
            return null;
        }
    }

    /**
     * Update file metadata in MinIO
     */
    async updateMetadata(
        key: string,
        metadata: Record<string, any>
    ): Promise<{ success: boolean; error?: string }> {
        try {
            // MinIO/S3 doesn't support updating metadata directly
            // We need to copy the object with new metadata
            const command = new CopyObjectCommand({
                Bucket: this.minioConfig.bucket,
                CopySource: `${this.minioConfig.bucket}/${key}`,
                Key: key,
                Metadata: metadata,
                MetadataDirective: 'REPLACE',
            });

            await this.s3Client.send(command);

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to update metadata for file ${key} in MinIO: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Perform health check for MinIO
     */
    protected async performHealthCheck(): Promise<boolean> {
        try {
            // Try to list objects to verify connection
            const command = new ListObjectsV2Command({
                Bucket: this.minioConfig.bucket,
                MaxKeys: 1,
            });

            await this.s3Client.send(command);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generate a file key for MinIO
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
     * Generate a presigned URL for MinIO
     */
    private async generatePresignedUrl(key: string, expiresIn: number): Promise<string> {
        const command = new GetObjectCommand({
            Bucket: this.minioConfig.bucket,
            Key: key,
        });

        return await getSignedUrl(this.s3Client, command, { expiresIn });
    }
}