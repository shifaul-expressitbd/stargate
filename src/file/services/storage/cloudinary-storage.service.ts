/**
 * Cloudinary Storage Service
 * Implements Cloudinary storage for images and media files
 */

import {
    Injectable
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { v2 as cloudinary, UploadApiErrorResponse, UploadApiResponse } from 'cloudinary';
import * as crypto from 'crypto';
import * as path from 'path';
import { MulterFile } from '../../interfaces/file-options.interface';
import type { CloudinaryStorageOptions } from '../../interfaces/storage-options.interface';
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
 * Cloudinary storage service implementation
 * Handles file storage using Cloudinary for optimized image/media processing
 */
@Injectable()
export class CloudinaryStorageService extends AbstractStorageService {
    private readonly cloudinaryConfig: CloudinaryStorageOptions;

    constructor(
        options: CloudinaryStorageOptions,
        configService: ConfigService
    ) {
        super(StorageProvider.CLOUDINARY, options, configService);
        this.cloudinaryConfig = options;

        // Configure Cloudinary
        cloudinary.config({
            cloud_name: this.cloudinaryConfig.cloudName,
            api_key: this.cloudinaryConfig.apiKey,
            api_secret: this.cloudinaryConfig.apiSecret,
            secure: this.cloudinaryConfig.secure ?? true,
        });
    }

    /**
     * Upload a file to Cloudinary
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
        const fileKey = key || this.generateFileKey(file);
        this.logger.log(`Starting Cloudinary upload for file key: ${fileKey}`);

        try {
            // Comprehensive file validation
            if (!file) {
                const errorMsg = 'File object is null or undefined';
                this.logger.error(errorMsg);
                return this.createFailureResponse(errorMsg, fileKey, { fileIsNull: true });
            }

            // Validate file properties for MulterFile
            if (!Buffer.isBuffer(file)) {
                const multerFile = file as MulterFile;

                // Log file object properties for debugging
                this.logger.debug(`File object properties:`, {
                    filename: multerFile.filename,
                    originalname: multerFile.originalname,
                    mimetype: multerFile.mimetype,
                    size: multerFile.size,
                    path: multerFile.path,
                    buffer: multerFile.buffer ? 'present' : 'absent',
                    encoding: multerFile.encoding,
                    destination: multerFile.destination,
                    fieldname: multerFile.fieldname,
                });

                // Validation: Check if file.path exists and is valid
                if (!multerFile.path) {
                    this.logger.warn(`File path is undefined, attempting fallback to buffer`);

                    if (!multerFile.buffer || multerFile.buffer.length === 0) {
                        const errorMsg = `File path is undefined and no buffer available. File properties: filename=${multerFile.filename}, originalname=${multerFile.originalname}, mimetype=${multerFile.mimetype}, size=${multerFile.size}`;
                        this.logger.error(errorMsg);
                        return this.createFailureResponse(errorMsg, fileKey, {
                            filePath: multerFile.path,
                            hasBuffer: !!multerFile.buffer,
                            bufferSize: multerFile.buffer?.length || 0,
                            originalName: multerFile.originalname,
                            mimeType: multerFile.mimetype,
                        });
                    }

                    // Fallback to buffer upload
                    this.logger.log(`Using buffer fallback for upload`);
                    file = multerFile.buffer;
                }

                // Additional validation for file path
                if (typeof multerFile.path !== 'string' || multerFile.path.trim() === '') {
                    const errorMsg = `Invalid file path: ${multerFile.path}. File properties: filename=${multerFile.filename}, originalname=${multerFile.originalname}`;
                    this.logger.error(errorMsg);
                    return this.createFailureResponse(errorMsg, fileKey, {
                        filePath: multerFile.path,
                        originalName: multerFile.originalname,
                        mimeType: multerFile.mimetype,
                    });
                }
            }

            // Prepare upload options
            const uploadOptions: any = {
                public_id: fileKey,
                resource_type: this.getResourceType(file, options?.mimeType),
                ...this.cloudinaryConfig.transformation,
            };

            // Add folder if configured - this requires signed upload
            if (this.cloudinaryConfig.folder) {
                uploadOptions.folder = this.cloudinaryConfig.folder;
            }

            // Add custom metadata if provided - this requires signed upload
            if (options?.metadata) {
                // Ensure metadata is properly formatted for Cloudinary
                const contextData = Object.entries(options.metadata)
                    .map(([key, value]) => `${key}=${value}`)
                    .join('|');
                uploadOptions.context = contextData;
                this.logger.debug(`Added custom metadata to upload options: ${contextData}`);
            }

            this.logger.log(`Upload options prepared:`, {
                public_id: uploadOptions.public_id,
                folder: uploadOptions.folder,
                resource_type: uploadOptions.resource_type,
                context: uploadOptions.context,
                timestamp: uploadOptions.timestamp,
                signature: uploadOptions.signature,
            });

            // Debug: Check Cloudinary configuration
            this.logger.debug(`Cloudinary config:`, {
                cloudName: this.cloudinaryConfig.cloudName,
                hasApiKey: !!this.cloudinaryConfig.apiKey,
                hasApiSecret: !!this.cloudinaryConfig.apiSecret,
                apiKeyLength: this.cloudinaryConfig.apiKey?.length,
                apiSecretLength: this.cloudinaryConfig.apiSecret?.length,
            });

            let result: UploadApiResponse;

            if (Buffer.isBuffer(file)) {
                this.logger.log(`Uploading buffer of size: ${file.length} bytes`);
                // Upload buffer
                result = await new Promise((resolve, reject) => {
                    const stream = cloudinary.uploader.upload_stream(
                        uploadOptions,
                        (error: UploadApiErrorResponse, uploadResult: UploadApiResponse) => {
                            if (error) {
                                this.logger.error(`Cloudinary buffer upload failed:`, {
                                    error: error.message,
                                    http_code: error.http_code,
                                    api_code: error.error?.code,
                                    api_message: error.error?.message,
                                });
                                reject(error);
                            } else {
                                this.logger.log(`Cloudinary buffer upload successful: ${uploadResult.public_id}`);
                                resolve(uploadResult);
                            }
                        }
                    );

                    // Write buffer to stream
                    stream.end(file);
                });
            } else {
                const multerFile = file as MulterFile;
                this.logger.log(`Uploading file from path: ${multerFile.path}`);

                // Upload from file path
                result = await new Promise((resolve, reject) => {
                    cloudinary.uploader.upload(
                        multerFile.path,
                        uploadOptions,
                        (error: UploadApiErrorResponse, uploadResult: UploadApiResponse) => {
                            if (error) {
                                this.logger.error(`Cloudinary file upload failed:`, {
                                    error: error.message,
                                    http_code: error.http_code,
                                    api_code: error.error?.code,
                                    api_message: error.error?.message,
                                    filePath: multerFile.path,
                                    originalName: multerFile.originalname,
                                });
                                reject(error);
                            } else {
                                this.logger.log(`Cloudinary file upload successful: ${uploadResult.public_id}`);
                                resolve(uploadResult);
                            }
                        }
                    );
                });
            }

            const successResponse = {
                fileId: result.public_id,
                key: result.public_id,
                url: result.secure_url,
                metadata: {
                    size: result.bytes,
                    mimeType: result.format ? `image/${result.format}` : 'application/octet-stream',
                    filename: result.original_filename,
                    uploadedAt: new Date(),
                },
                providerMetadata: {
                    width: result.width,
                    height: result.height,
                    format: result.format,
                    resource_type: result.resource_type,
                    version: result.version,
                },
                success: true,
            };

            this.logger.log(`Cloudinary upload completed successfully: ${result.public_id}`);
            return successResponse;

        } catch (error) {
            const errorMsg = `Failed to upload file to Cloudinary: ${error.message}`;
            this.logger.error(errorMsg, {
                error: error.message,
                stack: error.stack,
                fileKey,
                fileType: Buffer.isBuffer(file) ? 'buffer' : 'multer-file',
                fileProperties: !Buffer.isBuffer(file) ? {
                    filename: (file as MulterFile).filename,
                    originalname: (file as MulterFile).originalname,
                    path: (file as MulterFile).path,
                    mimetype: (file as MulterFile).mimetype,
                    size: (file as MulterFile).size,
                } : { bufferSize: (file as Buffer).length },
            });

            return this.createFailureResponse(errorMsg, fileKey, {
                errorDetails: {
                    message: error.message,
                    stack: error.stack,
                    name: error.name,
                },
                fileType: Buffer.isBuffer(file) ? 'buffer' : 'multer-file',
                fileProperties: !Buffer.isBuffer(file) ? {
                    filename: (file as MulterFile).filename,
                    originalname: (file as MulterFile).originalname,
                    path: (file as MulterFile).path,
                    mimetype: (file as MulterFile).mimetype,
                    size: (file as MulterFile).size,
                    hasBuffer: !!(file as MulterFile).buffer,
                } : { bufferSize: (file as Buffer).length },
            });
        }
    }

    /**
     * Create a standardized failure response with detailed error information
     */
    private createFailureResponse(
        errorMessage: string,
        fileKey: string,
        additionalDetails?: Record<string, any>
    ): StorageUploadResult {
        this.logger.error(`Upload failure response created:`, { errorMessage, fileKey, additionalDetails });

        return {
            fileId: '',
            key: '',
            url: '',
            metadata: {
                size: 0,
                mimeType: '',
                filename: fileKey || '',
                uploadedAt: new Date(),
            },
            success: false,
            error: errorMessage,
            errorDetails: additionalDetails,
        };
    }

    /**
     * Download a file from Cloudinary (returns optimized URL)
     */
    async download(key: string): Promise<StorageDownloadResult> {
        try {
            // For Cloudinary, download means getting the optimized URL
            // The actual download would be handled by the client using the URL
            const url = cloudinary.url(key, {
                secure: true,
                quality: 'auto',
                fetch_format: 'auto',
            });

            return {
                stream: undefined, // Cloudinary URLs are used directly
                metadata: {
                    size: 0, // Size not available without additional API call
                    mimeType: this.getMimeType(key),
                    lastModified: new Date(),
                },
                success: true,
            };
        } catch (error) {
            this.logger.error(`Failed to generate download URL for ${key}: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Delete a file from Cloudinary
     */
    async delete(key: string): Promise<StorageDeleteResult> {
        try {
            const result = await new Promise((resolve, reject) => {
                cloudinary.uploader.destroy(
                    key,
                    (error: UploadApiErrorResponse, destroyResult: any) => {
                        if (error) reject(error);
                        else resolve(destroyResult);
                    }
                );
            });

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to delete file ${key} from Cloudinary: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Check if a file exists in Cloudinary
     */
    async exists(key: string): Promise<StorageExistsResult> {
        try {
            // Cloudinary doesn't have a direct exists method
            // We can try to get resource details
            const resource = await new Promise<any>((resolve, reject) => {
                cloudinary.api.resource(
                    key,
                    (error: UploadApiErrorResponse, resourceResult: any) => {
                        if (error) reject(error);
                        else resolve(resourceResult);
                    }
                );
            });

            return {
                exists: true,
                metadata: {
                    size: resource.bytes,
                    mimeType: resource.format ? `image/${resource.format}` : 'application/octet-stream',
                    lastModified: new Date(resource.created_at),
                },
            };
        } catch (error) {
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
            let urlOptions: any = {
                secure: true,
                quality: 'auto',
                fetch_format: 'auto',
            };

            if (options?.download) {
                urlOptions.flags = 'attachment';
            }

            const url = cloudinary.url(key, urlOptions);

            return {
                url,
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
     * Get capabilities of Cloudinary storage
     */
    getCapabilities(): StorageCapabilities {
        return {
            resumableUpload: true,
            signedUrls: false, // Cloudinary handles URLs differently
            cdnIntegration: true,
            versioning: false,
            customMetadata: true,
            maxFileSize: 100 * 1024 * 1024, // 100MB default limit
            storageClasses: ['standard'],
            features: {
                imageOptimization: true,
                formatConversion: true,
                responsiveImages: true,
                videoProcessing: true,
            },
        };
    }

    /**
     * Copy a file within Cloudinary
     */
    async copy(fromKey: string, toKey: string): Promise<{ success: boolean; error?: string }> {
        try {
            await new Promise((resolve, reject) => {
                cloudinary.uploader.rename(
                    fromKey,
                    toKey,
                    (error: UploadApiErrorResponse, renameResult: any) => {
                        if (error) reject(error);
                        else resolve(renameResult);
                    }
                );
            });

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
     * List files in Cloudinary (limited implementation)
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
            const result = await new Promise<any>((resolve, reject) => {
                cloudinary.api.resources(
                    {
                        type: 'upload',
                        prefix,
                        max_results: options?.maxKeys || 100,
                        next_cursor: options?.continuationToken,
                    },
                    (error: UploadApiErrorResponse, resourcesResult: any) => {
                        if (error) reject(error);
                        else resolve(resourcesResult);
                    }
                );
            });

            const files = result.resources.map((resource: any) => ({
                key: resource.public_id,
                size: resource.bytes,
                lastModified: new Date(resource.created_at),
                mimeType: resource.format ? `image/${resource.format}` : 'application/octet-stream',
            }));

            return {
                files,
                continuationToken: result.next_cursor,
                truncated: !!result.next_cursor,
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
     * Get file metadata from Cloudinary
     */
    async getMetadata(key: string): Promise<{
        size: number;
        mimeType: string;
        lastModified: Date;
        etag?: string;
        customMetadata?: Record<string, any>;
    } | null> {
        try {
            const resource = await new Promise<any>((resolve, reject) => {
                cloudinary.api.resource(
                    key,
                    (error: UploadApiErrorResponse, resourceResult: any) => {
                        if (error) reject(error);
                        else resolve(resourceResult);
                    }
                );
            });

            return {
                size: resource.bytes,
                mimeType: resource.format ? `image/${resource.format}` : 'application/octet-stream',
                lastModified: new Date(resource.created_at),
                etag: `"${resource.version}"`,
                customMetadata: resource.context?.custom,
            };
        } catch (error) {
            this.logger.error(`Failed to get metadata for file ${key}: ${error.message}`, error.stack);
            return null;
        }
    }

    /**
     * Update file metadata in Cloudinary
     */
    async updateMetadata(
        key: string,
        metadata: Record<string, any>
    ): Promise<{ success: boolean; error?: string }> {
        try {
            await new Promise((resolve, reject) => {
                cloudinary.uploader.update_metadata(
                    metadata,
                    [key],
                    (error: UploadApiErrorResponse, updateResult: any) => {
                        if (error) reject(error);
                        else resolve(updateResult);
                    }
                );
            });

            return { success: true };
        } catch (error) {
            this.logger.error(`Failed to update metadata for file ${key}: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Perform health check for Cloudinary
     */
    protected async performHealthCheck(): Promise<boolean> {
        try {
            // Try to get usage stats to verify connection
            await new Promise((resolve, reject) => {
                cloudinary.api.usage(
                    (error: UploadApiErrorResponse, usageResult: any) => {
                        if (error) reject(error);
                        else resolve(usageResult);
                    }
                );
            });

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generate a file key for Cloudinary
     * Cloudinary will automatically add the file extension, so we exclude it from the key
     */
    private generateFileKey(file: MulterFile | Buffer): string {
        if (Buffer.isBuffer(file)) {
            const timestamp = Date.now();
            const random = crypto.randomBytes(4).toString('hex');
            return `buffer_${timestamp}_${random}`;
        }

        // For Cloudinary, don't include the extension as Cloudinary will add it automatically
        const ext = path.extname(file.originalname || 'file');
        const baseName = path.basename(file.originalname || 'file', ext);
        const timestamp = Date.now();
        const random = crypto.randomBytes(4).toString('hex');

        const filename = `${baseName}_${timestamp}_${random}`;

        // Add prefix if configured
        const prefix = this.cloudinaryConfig.folder ? `${this.cloudinaryConfig.folder}/` : '';
        return prefix + filename;
    }

    /**
     * Get Cloudinary resource type based on file
     */
    private getResourceType(file: MulterFile | Buffer, mimeType?: string): string {
        let type = 'auto';

        if (mimeType) {
            if (mimeType.startsWith('image/')) type = 'image';
            else if (mimeType.startsWith('video/')) type = 'video';
            else if (mimeType.startsWith('audio/')) type = 'video'; // Cloudinary treats audio as video
            else type = 'raw';
        } else if (!Buffer.isBuffer(file) && file.mimetype) {
            if (file.mimetype.startsWith('image/')) type = 'image';
            else if (file.mimetype.startsWith('video/')) type = 'video';
            else if (file.mimetype.startsWith('audio/')) type = 'video';
            else type = 'raw';
        }

        return type;
    }
}