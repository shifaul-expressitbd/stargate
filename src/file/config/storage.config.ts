/**
 * Storage Configuration Management
 * Handles storage provider configurations and settings
 */

import type { StorageClass } from '@aws-sdk/client-s3';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
    CloudinaryStorageOptions,
    GoogleCloudStorageOptions,
    LocalStorageOptions,
    MinIOStorageOptions,
    S3StorageOptions,
    StorageConfig,
} from '../interfaces/storage-options.interface';
import { StorageProvider } from '../interfaces/storage.interface';

/**
 * Storage configuration service
 * Manages storage provider configurations and settings
 */
@Injectable()
export class StorageConfigService {
    private storageConfig: StorageConfig;

    constructor(private configService: ConfigService) {
        this.loadConfiguration();
    }

    /**
     * Get the complete storage configuration
     */
    getConfig(): StorageConfig {
        return this.storageConfig;
    }

    /**
     * Get configuration for a specific provider
     */
    getProviderConfig<T extends keyof StorageConfig['providers']>(
        provider: T
    ): StorageConfig['providers'][T] {
        const config = this.storageConfig.providers[provider];
        if (!config) {
            throw new Error(`Storage provider '${provider}' is not configured`);
        }
        return config;
    }

    /**
     * Check if a provider is configured and enabled
     */
    isProviderEnabled(provider: StorageProvider): boolean {
        return provider in this.storageConfig.providers;
    }

    /**
     * Get the default storage provider
     */
    getDefaultProvider(): StorageProvider {
        return this.storageConfig.defaultProvider;
    }

    /**
     * Set the default storage provider
     */
    setDefaultProvider(provider: StorageProvider): void {
        if (!this.isProviderEnabled(provider)) {
            throw new Error(`Cannot set default provider to '${provider}': provider is not configured`);
        }
        this.storageConfig.defaultProvider = provider;
    }

    /**
     * Get all enabled providers
     */
    getEnabledProviders(): StorageProvider[] {
        return Object.keys(this.storageConfig.providers) as StorageProvider[];
    }

    /**
     * Add or update a provider configuration
     */
    updateProviderConfig<T extends StorageProvider>(
        provider: T,
        config: any // Using any to avoid complex union type issues
    ): void {
        this.storageConfig.providers[provider] = config;
        this.validateProviderConfig(provider, config);
    }

    /**
     * Remove a provider configuration
     */
    removeProviderConfig(provider: StorageProvider): void {
        if (this.storageConfig.defaultProvider === provider) {
            throw new Error(`Cannot remove default provider '${provider}'`);
        }
        delete this.storageConfig.providers[provider];
    }

    /**
     * Get global storage options
     */
    getGlobalOptions() {
        return this.storageConfig.global || {};
    }

    /**
     * Update global storage options
     */
    updateGlobalOptions(options: NonNullable<StorageConfig['global']>): void {
        this.storageConfig.global = { ...this.storageConfig.global, ...options };
    }

    /**
     * Validate provider configuration
     */
    private validateProviderConfig(provider: StorageProvider, config: any): void {
        switch (provider) {
            case StorageProvider.LOCAL:
                this.validateLocalConfig(config);
                break;
            case StorageProvider.CLOUDINARY:
                this.validateCloudinaryConfig(config);
                break;
            case StorageProvider.MINIO:
                this.validateMinIOConfig(config);
                break;
            case StorageProvider.S3:
                this.validateS3Config(config);
                break;
            case StorageProvider.GOOGLE_CLOUD:
                this.validateGoogleCloudConfig(config);
                break;
            default:
                throw new Error(`Unknown storage provider: ${provider}`);
        }
    }

    /**
     * Validate Local storage configuration
     */
    private validateLocalConfig(config: LocalStorageOptions): void {
        if (!config.baseDir) {
            throw new Error('Local storage requires baseDir configuration');
        }
        if (typeof config.baseDir !== 'string') {
            throw new Error('Local storage baseDir must be a string');
        }
    }

    /**
     * Validate Cloudinary configuration
     */
    private validateCloudinaryConfig(config: CloudinaryStorageOptions): void {
        const required = ['cloudName', 'apiKey', 'apiSecret'];
        for (const field of required) {
            if (!config[field as keyof CloudinaryStorageOptions]) {
                throw new Error(`Cloudinary storage requires ${field} configuration`);
            }
        }
    }

    /**
     * Validate MinIO configuration
     */
    private validateMinIOConfig(config: MinIOStorageOptions): void {
        const required = ['endPoint', 'accessKey', 'secretKey', 'bucket'];
        for (const field of required) {
            if (!config[field as keyof MinIOStorageOptions]) {
                throw new Error(`MinIO storage requires ${field} configuration`);
            }
        }
    }

    /**
     * Validate S3 configuration
     */
    private validateS3Config(config: S3StorageOptions): void {
        const required = ['region', 'accessKeyId', 'secretAccessKey', 'bucket'];
        for (const field of required) {
            if (!config[field as keyof S3StorageOptions]) {
                throw new Error(`S3 storage requires ${field} configuration`);
            }
        }
    }

    /**
     * Validate Google Cloud Storage configuration
     */
    private validateGoogleCloudConfig(config: GoogleCloudStorageOptions): void {
        const required = ['projectId', 'bucket'];
        for (const field of required) {
            if (!config[field as keyof GoogleCloudStorageOptions]) {
                throw new Error(`Google Cloud Storage requires ${field} configuration`);
            }
        }

        // Either keyFilename or credentials must be provided
        if (!config.keyFilename && !config.credentials) {
            throw new Error('Google Cloud Storage requires either keyFilename or credentials');
        }
    }

    /**
     * Load storage configuration from environment/config
     */
    private loadConfiguration(): void {
        // Default configuration structure
        this.storageConfig = {
            defaultProvider: StorageProvider.LOCAL,
            providers: {} as any, // Using any to avoid complex union type issues
            global: {
                timeout: 30000,
                retry: {
                    attempts: 3,
                    delay: 1000,
                    backoff: 'exponential',
                },
                enableLogging: true,
                defaultMetadata: {},
            },
        };

        // Load provider configurations from environment
        this.loadLocalConfig();
        this.loadCloudinaryConfig();
        this.loadMinIOConfig();
        this.loadS3Config();
        this.loadGoogleCloudConfig();

        // Set default provider from environment
        const defaultProvider = this.configService.get<string>('STORAGE_DEFAULT_PROVIDER');
        if (defaultProvider && this.isProviderEnabled(defaultProvider as StorageProvider)) {
            this.storageConfig.defaultProvider = defaultProvider as StorageProvider;
        }
    }

    /**
     * Load Local storage configuration
     */
    private loadLocalConfig(): void {
        const baseDir = this.configService.get<string>('STORAGE_LOCAL_BASE_DIR') || './uploads';
        const directoryStrategy = this.configService.get<string>('STORAGE_LOCAL_DIRECTORY_STRATEGY') || 'date';

        this.storageConfig.providers[StorageProvider.LOCAL] = {
            provider: StorageProvider.LOCAL,
            baseDir,
            directoryStrategy: directoryStrategy as 'flat' | 'date' | 'user' | 'custom',
            createDirs: true,
        };
    }

    /**
     * Load Cloudinary configuration
     */
    private loadCloudinaryConfig(): void {
        const cloudName = this.configService.get<string>('STORAGE_CLOUDINARY_CLOUD_NAME');
        const apiKey = this.configService.get<string>('STORAGE_CLOUDINARY_API_KEY');
        const apiSecret = this.configService.get<string>('STORAGE_CLOUDINARY_API_SECRET');

        if (cloudName && apiKey && apiSecret) {
            this.storageConfig.providers[StorageProvider.CLOUDINARY] = {
                provider: StorageProvider.CLOUDINARY,
                cloudName,
                apiKey,
                apiSecret,
                folder: this.configService.get<string>('STORAGE_CLOUDINARY_FOLDER'),
                secure: true,
            };
        }
    }

    /**
     * Load MinIO configuration
     */
    private loadMinIOConfig(): void {
        const endPoint = this.configService.get<string>('STORAGE_MINIO_ENDPOINT');
        const accessKey = this.configService.get<string>('STORAGE_MINIO_ACCESS_KEY');
        const secretKey = this.configService.get<string>('STORAGE_MINIO_SECRET_KEY');
        const bucket = this.configService.get<string>('STORAGE_MINIO_BUCKET');

        if (endPoint && accessKey && secretKey && bucket) {
            this.storageConfig.providers[StorageProvider.MINIO] = {
                provider: StorageProvider.MINIO,
                endPoint,
                port: this.configService.get<number>('STORAGE_MINIO_PORT'),
                useSSL: this.configService.get<boolean>('STORAGE_MINIO_USE_SSL', true),
                accessKey,
                secretKey,
                bucket,
                region: this.configService.get<string>('STORAGE_MINIO_REGION'),
            };
        }
    }

    /**
     * Load S3 configuration
     */
    private loadS3Config(): void {
        const region = this.configService.get<string>('STORAGE_S3_REGION');
        const accessKeyId = this.configService.get<string>('STORAGE_S3_ACCESS_KEY_ID');
        const secretAccessKey = this.configService.get<string>('STORAGE_S3_SECRET_ACCESS_KEY');
        const bucket = this.configService.get<string>('STORAGE_S3_BUCKET');

        if (region && accessKeyId && secretAccessKey && bucket) {
            const storageClassValue = this.configService.get<string>('STORAGE_S3_STORAGE_CLASS', 'STANDARD');

            this.storageConfig.providers[StorageProvider.S3] = {
                provider: StorageProvider.S3,
                region,
                accessKeyId,
                secretAccessKey,
                bucket,
                endpoint: this.configService.get<string>('STORAGE_S3_ENDPOINT'),
                forcePathStyle: this.configService.get<boolean>('STORAGE_S3_FORCE_PATH_STYLE', false),
                storageClass: storageClassValue as StorageClass,
            };
        }
    }

    /**
     * Load Google Cloud Storage configuration
     */
    private loadGoogleCloudConfig(): void {
        const projectId = this.configService.get<string>('STORAGE_GCS_PROJECT_ID');
        const bucket = this.configService.get<string>('STORAGE_GCS_BUCKET');
        const keyFilename = this.configService.get<string>('STORAGE_GCS_KEY_FILE');

        if (projectId && bucket) {
            this.storageConfig.providers[StorageProvider.GOOGLE_CLOUD] = {
                provider: StorageProvider.GOOGLE_CLOUD,
                projectId,
                bucket,
                keyFilename,
                storageClass: this.configService.get<string>('STORAGE_GCS_STORAGE_CLASS', 'STANDARD'),
                versioning: this.configService.get<boolean>('STORAGE_GCS_VERSIONING', false),
            };
        }
    }

    /**
     * Get configuration summary for monitoring/debugging
     */
    getConfigurationSummary(): {
        defaultProvider: StorageProvider;
        enabledProviders: StorageProvider[];
        providerHealth: Record<StorageProvider, boolean>;
    } {
        const enabledProviders = this.getEnabledProviders();
        const providerHealth = {} as Record<StorageProvider, boolean>;

        for (const provider of enabledProviders) {
            // In a real implementation, this would check actual provider health
            providerHealth[provider] = true;
        }

        return {
            defaultProvider: this.storageConfig.defaultProvider,
            enabledProviders,
            providerHealth,
        };
    }
}