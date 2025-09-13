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
        const provider = options?.preferredProvider ||
            this.storageSelectorService.selectStorage(file);

        const storageService = this.getStorageService(provider);

        return await storageService.upload(file, undefined, {
            mimeType: options?.mimeType,
            metadata: options?.metadata,
        });
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
        const config = this.storageConfigService.getProviderConfig(provider);

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
}