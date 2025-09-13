/**
 * Storage Manager Service
 * Manages multiple storage providers and handles storage operations
 */

import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ModuleRef } from '@nestjs/core';
import { StorageConfigService } from '../config/storage.config';
import { MulterFile } from '../interfaces/file-options.interface';
import { IStorageService } from '../interfaces/istorage-service.interface';
import { StorageDeleteResult, StorageDownloadResult, StorageProvider, StorageUploadResult, StorageUrlResult } from '../interfaces/storage.interface';
import { StorageSelectorService } from './storage-selector.service';
import { CloudflareR2StorageService } from './storage/cloudflare-r2-storage.service';
import { CloudinaryStorageService } from './storage/cloudinary-storage.service';
import { GoogleCloudStorageService } from './storage/google-cloud-storage.service';
import { LocalStorageService } from './storage/local-storage.service';
import { MinIOStorageService } from './storage/minio-storage.service';
import { S3StorageService } from './storage/s3-storage.service';

/**
 * Storage manager service
 * Provides unified interface for all storage operations across multiple providers
 */
@Injectable()
export class StorageManagerService implements OnModuleInit {
    private readonly logger = new Logger(StorageManagerService.name);
    private storageServices: Map<StorageProvider, IStorageService> = new Map();

    constructor(
        private configService: ConfigService,
        private storageConfigService: StorageConfigService,
        private storageSelectorService: StorageSelectorService,
        private moduleRef: ModuleRef
    ) { }

    async onModuleInit() {
        await this.initializeStorageServices();
    }

    /**
     * Upload a file using the most appropriate storage provider
     */
    async uploadFile(
        file: MulterFile,
        options?: {
            preferredProvider?: StorageProvider;
            mimeType?: string;
            metadata?: Record<string, any>;
        }
    ): Promise<StorageUploadResult> {
        this.logger.debug(`StorageManager uploadFile called for: ${file.originalname}`, {
            originalname: file.originalname,
            mimetype: file.mimetype,
            size: file.size,
            preferredProvider: options?.preferredProvider,
            hasMetadata: !!options?.metadata,
        });

        const provider = options?.preferredProvider ||
            this.storageSelectorService.selectStorage(file);

        this.logger.log(`Selected storage provider: ${provider} for file: ${file.originalname}`);

        const storageService = this.getStorageService(provider);

        this.logger.debug(`Calling storage service upload for provider: ${provider}`);

        try {
            const result = await storageService.upload(file, undefined, {
                mimeType: options?.mimeType,
                metadata: options?.metadata,
            });

            this.logger.log(`Storage upload result for ${file.originalname}:`, {
                success: result.success,
                key: result.key,
                provider,
                error: result.error,
            });

            // Enhanced error logging for debugging
            if (!result.success && result.error) {
                this.logger.error(`Upload failed for provider ${provider}, file ${file.originalname}:`, {
                    error: result.error,
                    fileSize: file.size,
                    mimeType: file.mimetype,
                    provider,
                    availableProviders: this.getAvailableProviders(),
                    providerConfigured: this.isProviderAvailable(provider)
                });
            }

            return result;
        } catch (uploadError) {
            this.logger.error(`Exception during upload for provider ${provider}, file ${file.originalname}:`, {
                error: uploadError.message,
                stack: uploadError.stack,
                fileSize: file.size,
                mimeType: file.mimetype,
                provider,
                availableProviders: this.getAvailableProviders()
            });

            // Return failed result
            return {
                success: false,
                error: uploadError.message,
                fileId: '',
                key: '',
                url: '',
                metadata: {
                    size: file.size,
                    mimeType: file.mimetype,
                    filename: file.originalname,
                    uploadedAt: new Date()
                }
            };
        }
    }

    /**
     * Download a file from storage
     */
    async downloadFile(
        key: string,
        provider?: StorageProvider
    ): Promise<StorageDownloadResult> {
        const storageService = this.getStorageServiceForKey(key, provider);
        return await storageService.download(key);
    }

    /**
     * Delete a file from storage
     */
    async deleteFile(
        key: string,
        provider?: StorageProvider
    ): Promise<StorageDeleteResult> {
        const storageService = this.getStorageServiceForKey(key, provider);
        return await storageService.delete(key);
    }

    /**
     * Generate a URL for file access
     */
    async getFileUrl(
        key: string,
        provider?: StorageProvider,
        options?: {
            expiresIn?: number;
            signed?: boolean;
            download?: boolean;
        }
    ): Promise<StorageUrlResult> {
        const storageService = this.getStorageServiceForKey(key, provider);
        return await storageService.getUrl(key, options);
    }

    /**
     * Get storage service for a specific provider
     */
    getStorageService(provider: StorageProvider): IStorageService {
        const service = this.storageServices.get(provider);
        if (!service) {
            throw new Error(`Storage provider '${provider}' is not available or not configured`);
        }
        return service;
    }

    /**
     * Get all available storage providers
     */
    getAvailableProviders(): StorageProvider[] {
        return Array.from(this.storageServices.keys());
    }

    /**
     * Check if a provider is available
     */
    isProviderAvailable(provider: StorageProvider): boolean {
        return this.storageServices.has(provider);
    }

    /**
     * Get storage service for a key (determines provider from key if possible)
     */
    private getStorageServiceForKey(key: string, provider?: StorageProvider): IStorageService {
        if (provider) {
            return this.getStorageService(provider);
        }

        // Try to determine provider from key pattern
        // This is a simple heuristic - in production, you might store provider info in metadata
        if (key.startsWith('cloudinary://')) {
            return this.getStorageService(StorageProvider.CLOUDINARY);
        } else if (key.startsWith('s3://')) {
            return this.getStorageService(StorageProvider.S3);
        } else if (key.startsWith('r2://')) {
            return this.getStorageService(StorageProvider.CLOUDFLARE_R2);
        } else {
            // Default to local storage
            return this.getStorageService(StorageProvider.LOCAL);
        }
    }

    /**
     * Initialize storage services based on configuration
     */
    private async initializeStorageServices(): Promise<void> {
        const enabledProviders = this.storageConfigService.getEnabledProviders();

        for (const provider of enabledProviders) {
            try {
                await this.initializeStorageService(provider);
                this.logger.log(`Initialized storage provider: ${provider}`);
            } catch (error) {
                this.logger.error(`Failed to initialize storage provider ${provider}: ${error.message}`, error.stack);
            }
        }

        if (this.storageServices.size === 0) {
            throw new Error('No storage providers could be initialized');
        }

        this.logger.log(`Storage manager initialized with ${this.storageServices.size} providers`);
    }

    /**
     * Initialize a specific storage service
     */
    private async initializeStorageService(provider: StorageProvider): Promise<void> {
        this.logger.debug(`Initializing storage service for provider: ${provider}`);

        const config = this.storageConfigService.getProviderConfig(provider);

        this.logger.debug(`Retrieved config for ${provider}:`, {
            hasConfig: !!config,
            configKeys: config ? Object.keys(config) : [],
        });

        let service: IStorageService;

        switch (provider) {
            case StorageProvider.LOCAL:
                service = new LocalStorageService(config as any, this.configService);
                break;

            case StorageProvider.CLOUDINARY:
                service = new CloudinaryStorageService(config as any, this.configService);
                break;

            case StorageProvider.S3:
                service = new S3StorageService(config as any, this.configService);
                break;

            case StorageProvider.CLOUDFLARE_R2:
                service = new CloudflareR2StorageService(config as any, this.configService);
                break;

            case StorageProvider.MINIO:
                service = new MinIOStorageService(config as any, this.configService);
                break;

            case StorageProvider.GOOGLE_CLOUD:
                service = new GoogleCloudStorageService(config as any, this.configService);
                break;

            default:
                throw new Error(`Unknown storage provider: ${provider}`);
        }

        this.storageServices.set(provider, service);
        this.logger.debug(`Successfully initialized storage service: ${provider}`);
    }

    /**
     * Get storage usage statistics
     */
    getStorageStats() {
        return this.storageSelectorService.getStorageStats();
    }

    /**
     * Get storage configuration summary
     */
    getConfigurationSummary() {
        return this.storageConfigService.getConfigurationSummary();
    }

    /**
     * Perform health check on a specific provider
     */
    async checkProviderHealth(provider: StorageProvider): Promise<{
        healthy: boolean;
        error?: string;
        responseTime?: number;
    }> {
        const startTime = Date.now();

        try {
            const service = this.getStorageService(provider);

            // Simple health check - try to get a test URL
            const testResult = await service.getUrl('health-check-test-key', { expiresIn: 60 });

            const responseTime = Date.now() - startTime;

            if (testResult.success) {
                this.logger.debug(`Health check passed for provider ${provider} (${responseTime}ms)`);
                return { healthy: true, responseTime };
            } else {
                this.logger.warn(`Health check failed for provider ${provider}: ${testResult.error}`);
                return { healthy: false, error: testResult.error, responseTime };
            }
        } catch (error) {
            const responseTime = Date.now() - startTime;
            this.logger.error(`Health check exception for provider ${provider}:`, {
                error: error.message,
                responseTime
            });
            return { healthy: false, error: error.message, responseTime };
        }
    }

    /**
     * Check health of all available providers
     */
    async checkAllProvidersHealth(): Promise<Record<StorageProvider, {
        healthy: boolean;
        error?: string;
        responseTime?: number;
    }>> {
        const results: Record<string, any> = {};
        const providers = this.getAvailableProviders();

        for (const provider of providers) {
            results[provider] = await this.checkProviderHealth(provider);
        }

        this.logger.log('Provider health check results:', results);
        return results;
    }
}