/**
 * S3 Storage Service
 * Implements AWS S3 storage for large files and backup
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
import type { S3StorageOptions } from '../../interfaces/storage-options.interface';
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
 * S3 storage service implementation
 * Handles file storage using AWS S3 for scalable cloud storage
 */
@Injectable()
export class S3StorageService extends AbstractStorageService {
    private readonly s3Client: S3Client;
    private readonly s3Config: S3StorageOptions;

    constructor(
        options: S3StorageOptions,
        configService: ConfigService
    ) {
        super(StorageProvider.S3, options, configService);
        this.s3Config = options;

        this.s3Client = new S3Client({
            region: this.s3Config.region,
            credentials: {
                accessKeyId: this.s3Config.accessKeyId,
                secretAccessKey: this.s3Config.secretAccessKey,
            },
            endpoint: this.s3Config.endpoint,
            forcePathStyle: this.s3Config.forcePathStyle ?? false,
        });
    }

    /**
     * Upload a file to S3
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

            this.logger.debug(`S3 upload starting for key: ${fileKey}`, {
                bucket: this.s3Config.bucket,
                region: this.s3Config.region,
                hasKey: !!key,
                generatedKey: fileKey,
            });

            let body: Buffer;
            let contentType: string;
            let contentLength: number;

            if (Buffer.isBuffer(file)) {
                body = file;
                contentType = options?.mimeType || 'application/octet-stream';
                contentLength = file.length;
                this.logger.debug(`Using buffer body, size: ${contentLength}`);
            } else {
                this.logger.debug(`Reading file from path: ${file.path}`);
                body = require('fs').readFileSync(file.path);
                contentType = options?.mimeType || file.mimetype;
                contentLength = file.size;
                this.logger.debug(`Read file from disk, size: ${contentLength}`);
            }

            const uploadParams = {
                Bucket: this.s3Config.bucket,
                Key: fileKey,
                Body: body,
                ContentType: contentType,
                ContentLength: contentLength,
                Metadata: options?.metadata,
                StorageClass: this.s3Config.storageClass,
                ServerSideEncryption: this.s3Config.serverSideEncryption,
            };

            this.logger.debug(`S3 upload params prepared:`, {
                bucket: uploadParams.Bucket,
                key: uploadParams.Key,
                contentType: uploadParams.ContentType,
                contentLength: uploadParams.ContentLength,
                storageClass: uploadParams.StorageClass,
                hasMetadata: !!uploadParams.Metadata,
            });

            const command = new PutObjectCommand(uploadParams);
            this.logger.debug(`Sending PutObjectCommand to S3`);
            const result = await this.s3Client.send(command);

            this.logger.debug(`S3 upload command result:`, {
                etag: result.ETag,
                versionId: result.VersionId,
            });

            const url = this.s3Config.publicUrl
                ? `${this.s3Config.publicUrl}/${fileKey}`
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
            this.logger.error(`Failed to upload file to S3: ${error.message}`, {
                error: error.message,
                stack: error.stack,
                bucket: this.s3Config.bucket,
                region: this.s3Config.region,
                fileKey: key,
                errorCode: error.code,
                errorName: error.name,
                requestId: error.$metadata?.requestId,
                httpStatusCode: error.$metadata?.httpStatusCode,
            });
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
     * Download a file from S3
     */
    async download(key: string): Promise<StorageDownloadResult> {
        try {
            const command = new GetObjectCommand({
                Bucket: this.s3Config.bucket,
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
            this.logger.error(`Failed to download file ${key} from S3: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Delete a file from S3
     */
    async delete(key: string): Promise<StorageDeleteResult> {
        try {
            const command = new DeleteObjectCommand({
                Bucket: this.s3Config.bucket,
                Key: key,
            });

            await this.s3Client.send(command);

            this.logger.log(`File deleted successfully: ${key}`);
            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to delete file ${key} from S3: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Check if a file exists in S3
     */
    async exists(key: string): Promise<StorageExistsResult> {
        try {
            const command = new HeadObjectCommand({
                Bucket: this.s3Config.bucket,
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
            this.logger.error(`Failed to check existence of file ${key} in S3: ${error.message}`, error.stack);
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
            if (this.s3Config.publicUrl && !options?.signed) {
                // Return public URL
                const url = `${this.s3Config.publicUrl}/${key}`;
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
     * Get capabilities of S3 storage
     */
    getCapabilities(): StorageCapabilities {
        return {
            resumableUpload: true,
            signedUrls: true,
            cdnIntegration: true,
            versioning: true,
            customMetadata: true,
            maxFileSize: 5 * 1024 * 1024 * 1024 * 1024, // 5TB
            storageClasses: [
                'STANDARD',
                'STANDARD_IA',
                'ONEZONE_IA',
                'GLACIER',
                'DEEP_ARCHIVE',
                'INTELLIGENT_TIERING',
            ],
            features: {
                lifecycleManagement: true,
                crossRegionReplication: true,
                encryptionAtRest: true,
            },
        };
    }

    /**
     * Copy a file within S3
     */
    async copy(fromKey: string, toKey: string): Promise<{ success: boolean; error?: string }> {
        try {
            const command = new CopyObjectCommand({
                Bucket: this.s3Config.bucket,
                CopySource: `${this.s3Config.bucket}/${fromKey}`,
                Key: toKey,
                StorageClass: this.s3Config.storageClass,
            });

            await this.s3Client.send(command);

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to copy file from ${fromKey} to ${toKey} in S3: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * List files in S3
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
                Bucket: this.s3Config.bucket,
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
            this.logger.error(`Failed to list files in S3: ${error.message}`, error.stack);
            return {
                files: [],
                truncated: false,
            };
        }
    }

    /**
     * Get file metadata from S3
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
                Bucket: this.s3Config.bucket,
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
            this.logger.error(`Failed to get metadata for file ${key} from S3: ${error.message}`, error.stack);
            return null;
        }
    }

    /**
     * Update file metadata in S3
     */
    async updateMetadata(
        key: string,
        metadata: Record<string, any>
    ): Promise<{ success: boolean; error?: string }> {
        try {
            // S3 doesn't support updating metadata directly
            // We need to copy the object with new metadata
            const command = new CopyObjectCommand({
                Bucket: this.s3Config.bucket,
                CopySource: `${this.s3Config.bucket}/${key}`,
                Key: key,
                Metadata: metadata,
                MetadataDirective: 'REPLACE',
            });

            await this.s3Client.send(command);

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to update metadata for file ${key} in S3: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Perform health check for S3
     */
    protected async performHealthCheck(): Promise<boolean> {
        try {
            // Try to list objects to verify connection
            const command = new ListObjectsV2Command({
                Bucket: this.s3Config.bucket,
                MaxKeys: 1,
            });

            await this.s3Client.send(command);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generate a file key for S3
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
     * Generate a presigned URL for S3
     */
    private async generatePresignedUrl(key: string, expiresIn: number): Promise<string> {
        const command = new GetObjectCommand({
            Bucket: this.s3Config.bucket,
            Key: key,
        });

        return await getSignedUrl(this.s3Client, command, { expiresIn });
    }
}