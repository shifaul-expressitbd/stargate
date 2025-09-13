/**
 * Storage Selector Service
 * Intelligently chooses the appropriate storage backend based on file properties
 */

import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { StorageConfigService } from '../config/storage.config';
import { FileCategory } from '../interfaces/file-metadata.interface';
import { MulterFile } from '../interfaces/file-options.interface';
import { StorageProvider } from '../interfaces/storage.interface';

/**
 * Storage selection criteria
 */
export interface StorageSelectionCriteria {
    /** File size in bytes */
    fileSize: number;

    /** MIME type */
    mimeType: string;

    /** File category */
    category: FileCategory;

    /** Whether the file should be publicly accessible */
    publicAccess?: boolean;

    /** Required retention period in days */
    retentionDays?: number;

    /** Cost sensitivity (lower = more cost sensitive) */
    costSensitivity?: 'low' | 'medium' | 'high';

    /** Performance requirements */
    performance?: 'low' | 'medium' | 'high';

    /** Backup requirements */
    backupRequired?: boolean;

    /** Geographic distribution needed */
    globalDistribution?: boolean;
}

/**
 * Storage recommendation result
 */
export interface StorageRecommendation {
    /** Recommended storage provider */
    provider: StorageProvider;

    /** Reasoning for the recommendation */
    reasoning: string[];

    /** Estimated cost per GB per month */
    estimatedCostPerGB?: number;

    /** Performance characteristics */
    performance: {
        latency: 'low' | 'medium' | 'high';
        throughput: 'low' | 'medium' | 'high';
        availability: number; // percentage
    };

    /** Compliance features */
    compliance: {
        encryption: boolean;
        auditLogs: boolean;
        dataResidency: boolean;
    };
}

/**
 * Storage selector service
 * Provides intelligent storage backend selection based on file characteristics and requirements
 */
@Injectable()
export class StorageSelectorService {
    private readonly logger = new Logger(StorageSelectorService.name);

    constructor(
        private configService: ConfigService,
        private storageConfigService: StorageConfigService
    ) { }

    /**
     * Select the most appropriate storage backend for a file
     */
    selectStorage(
        file: MulterFile,
        criteria?: Partial<StorageSelectionCriteria>
    ): StorageProvider {
        const fileCriteria = this.buildCriteria(file, criteria);
        const recommendation = this.getRecommendation(fileCriteria);

        this.logger.log(
            `Selected ${recommendation.provider} storage for file ${file.originalname} (${fileCriteria.category}, ${fileCriteria.fileSize} bytes)`
        );

        // Enhanced logging for debugging
        this.logger.debug(`Storage selection details for ${file.originalname}:`, {
            criteria: fileCriteria,
            recommendation: {
                provider: recommendation.provider,
                reasoning: recommendation.reasoning,
                estimatedCost: recommendation.estimatedCostPerGB,
                performance: recommendation.performance
            },
            allConfiguredProviders: this.getAvailableProviders()
        });

        return recommendation.provider;
    }

    /**
     * Get detailed recommendation for storage selection
     */
    getRecommendation(criteria: StorageSelectionCriteria): StorageRecommendation {
        const recommendations = this.evaluateAllProviders(criteria);

        // Sort by score (higher is better)
        recommendations.sort((a, b) => b.score - a.score);

        return {
            provider: recommendations[0].provider,
            reasoning: recommendations[0].reasoning,
            estimatedCostPerGB: recommendations[0].estimatedCostPerGB,
            performance: recommendations[0].performance,
            compliance: recommendations[0].compliance,
        };
    }

    /**
     * Get all available storage providers
     */
    getAvailableProviders(): StorageProvider[] {
        const config = this.storageConfigService.getConfig();
        return Object.keys(config.providers) as StorageProvider[];
    }

    /**
     * Check if a provider is available and healthy
     */
    async isProviderAvailable(provider: StorageProvider): Promise<boolean> {
        // In a real implementation, this would check provider health
        // For now, just check if it's configured
        const config = this.storageConfigService.getConfig();
        return provider in config.providers;
    }

    /**
     * Get storage statistics by provider
     */
    getStorageStats(): Record<StorageProvider, {
        totalFiles: number;
        totalSize: number;
        avgFileSize: number;
        utilizationRate: number;
    }> {
        // This would typically query actual storage usage
        // For now, return mock data
        const stats = {} as Record<StorageProvider, {
            totalFiles: number;
            totalSize: number;
            avgFileSize: number;
            utilizationRate: number;
        }>;

        for (const provider of this.getAvailableProviders()) {
            stats[provider] = {
                totalFiles: 0,
                totalSize: 0,
                avgFileSize: 0,
                utilizationRate: 0,
            };
        }

        return stats;
    }

    /**
     * Build selection criteria from file and additional parameters
     */
    private buildCriteria(
        file: MulterFile,
        criteria?: Partial<StorageSelectionCriteria>
    ): StorageSelectionCriteria {
        return {
            fileSize: file.size,
            mimeType: file.mimetype,
            category: this.determineFileCategory(file),
            publicAccess: criteria?.publicAccess ?? false,
            retentionDays: criteria?.retentionDays ?? 365, // Default 1 year
            costSensitivity: criteria?.costSensitivity ?? 'medium',
            performance: criteria?.performance ?? 'medium',
            backupRequired: criteria?.backupRequired ?? true,
            globalDistribution: criteria?.globalDistribution ?? false,
        };
    }

    /**
     * Determine file category from MIME type
     */
    private determineFileCategory(file: MulterFile): FileCategory {
        const mimeType = file.mimetype.toLowerCase();

        if (mimeType.startsWith('image/')) return FileCategory.IMAGE;
        if (mimeType.startsWith('video/')) return FileCategory.VIDEO;
        if (mimeType.startsWith('audio/')) return FileCategory.AUDIO;

        if (mimeType.includes('pdf') || mimeType.includes('document')) return FileCategory.DOCUMENT;
        if (mimeType.includes('spreadsheet') || mimeType.includes('excel')) return FileCategory.SPREADSHEET;
        if (mimeType.includes('presentation') || mimeType.includes('powerpoint')) return FileCategory.PRESENTATION;

        if (mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('7z')) return FileCategory.ARCHIVE;

        if (mimeType.includes('text') || mimeType.includes('json') || mimeType.includes('xml')) return FileCategory.TEXT;
        if (mimeType.includes('javascript') || mimeType.includes('typescript')) return FileCategory.CODE;

        return FileCategory.OTHER;
    }

    /**
     * Evaluate all providers and return scored recommendations
     */
    private evaluateAllProviders(criteria: StorageSelectionCriteria): Array<{
        provider: StorageProvider;
        score: number;
        reasoning: string[];
        estimatedCostPerGB: number;
        performance: any;
        compliance: any;
    }> {
        const evaluations: Array<{
            provider: StorageProvider;
            score: number;
            reasoning: string[];
            estimatedCostPerGB: number;
            performance: any;
            compliance: any;
        }> = [];

        for (const provider of this.getAvailableProviders()) {
            const evaluation = this.evaluateProvider(provider, criteria);
            evaluations.push(evaluation);
        }

        return evaluations;
    }

    /**
     * Evaluate a specific provider against the criteria
     */
    private evaluateProvider(
        provider: StorageProvider,
        criteria: StorageSelectionCriteria
    ): {
        provider: StorageProvider;
        score: number;
        reasoning: string[];
        estimatedCostPerGB: number;
        performance: any;
        compliance: any;
    } {
        let score = 0;
        const reasoning: string[] = [];
        let estimatedCostPerGB = 0;
        let performance = { latency: 'medium', throughput: 'medium', availability: 99.9 };
        let compliance = { encryption: true, auditLogs: true, dataResidency: true };

        switch (provider) {
            case StorageProvider.LOCAL:
                estimatedCostPerGB = 0; // No cost
                performance = { latency: 'low', throughput: 'high', availability: 99.5 };
                compliance = { encryption: false, auditLogs: false, dataResidency: true };

                // Local storage is ideal for large files (> 50MB) - cost-effective
                if (criteria.fileSize > 50 * 1024 * 1024) { // > 50MB
                    score += 50;
                    reasoning.push('Cost-effective for large files over 50MB');
                }

                if (!criteria.globalDistribution) {
                    score += 25;
                    reasoning.push('Perfect for local/single-region access');
                }

                if (criteria.costSensitivity === 'high') {
                    score += 25;
                    reasoning.push('Zero cost storage');
                }
                break;

            case StorageProvider.CLOUDINARY:
                estimatedCostPerGB = 0.15; // Example pricing
                performance = { latency: 'low', throughput: 'high', availability: 99.9 };
                compliance = { encryption: true, auditLogs: true, dataResidency: false };

                // Cloudinary is optimized for images under 5MB
                if (criteria.category === FileCategory.IMAGE && criteria.fileSize < 5 * 1024 * 1024) { // < 5MB
                    score += 50;
                    reasoning.push('Optimized for image processing and delivery under 5MB');
                }

                if (criteria.category === FileCategory.VIDEO) {
                    score += 40;
                    reasoning.push('Excellent for video storage and streaming');
                }

                if (criteria.publicAccess) {
                    score += 30;
                    reasoning.push('Built-in CDN for fast global distribution');
                }

                if (criteria.performance === 'high') {
                    score += 20;
                    reasoning.push('High-performance media optimization');
                }
                break;

            case StorageProvider.S3:
                estimatedCostPerGB = 0.023; // Standard S3 pricing
                performance = { latency: 'medium', throughput: 'high', availability: 99.999 };
                compliance = { encryption: true, auditLogs: true, dataResidency: true };

                // S3 is ideal for documents under 50MB - durability & accessibility
                if (criteria.category === FileCategory.DOCUMENT && criteria.fileSize < 50 * 1024 * 1024) { // < 50MB
                    score += 50;
                    reasoning.push('Excellent for documents under 50MB - durability and accessibility');
                }

                // Also good for other file types
                score += 25; // Base score for versatility

                if (criteria.backupRequired) {
                    score += 25;
                    reasoning.push('Excellent for backup and archival');
                }

                if (criteria.globalDistribution) {
                    score += 20;
                    reasoning.push('Global distribution capabilities');
                }

                if (criteria.retentionDays && criteria.retentionDays > 365) {
                    score += 15;
                    reasoning.push('Long-term retention support');
                }
                break;

            case StorageProvider.MINIO:
                estimatedCostPerGB = 0.01; // Very low cost
                performance = { latency: 'medium', throughput: 'medium', availability: 99.5 };
                compliance = { encryption: true, auditLogs: true, dataResidency: true };

                // MinIO is good for private cloud storage
                if (!criteria.publicAccess) {
                    score += 30;
                    reasoning.push('Excellent for private/enterprise storage');
                }

                if (criteria.costSensitivity === 'high') {
                    score += 25;
                    reasoning.push('Very cost-effective storage');
                }

                if (criteria.category === FileCategory.DOCUMENT || criteria.category === FileCategory.ARCHIVE) {
                    score += 20;
                    reasoning.push('Well suited for documents and archives');
                }
                break;

            case StorageProvider.CLOUDFLARE_R2:
                estimatedCostPerGB = 0.015; // R2 pricing (cost-effective)
                performance = { latency: 'low', throughput: 'high', availability: 99.999 };
                compliance = { encryption: true, auditLogs: true, dataResidency: true };

                // R2 is best for general files (<5GB), global distribution, cost-effective storage
                if (criteria.fileSize < 5 * 1024 * 1024 * 1024) { // < 5GB
                    score += 50;
                    reasoning.push('Optimized for general files under 5GB');
                }

                if (criteria.globalDistribution) {
                    score += 40;
                    reasoning.push('Excellent global distribution capabilities');
                }

                if (criteria.costSensitivity === 'high') {
                    score += 30;
                    reasoning.push('Cost-effective storage option');
                }

                if (criteria.performance === 'medium' || criteria.performance === 'high') {
                    score += 25;
                    reasoning.push('Good performance for most use cases');
                }

                // Base score for versatility
                score += 20;
                reasoning.push('Versatile storage for various file types');
                break;

            case StorageProvider.GOOGLE_CLOUD:
                estimatedCostPerGB = 0.026; // GCS pricing
                performance = { latency: 'medium', throughput: 'high', availability: 99.999 };
                compliance = { encryption: true, auditLogs: true, dataResidency: true };

                // Google Cloud Storage is enterprise-grade
                if (criteria.category === FileCategory.IMAGE) {
                    score += 25;
                    reasoning.push('Good for image storage with AI processing');
                }

                if (criteria.backupRequired) {
                    score += 20;
                    reasoning.push('Enterprise-grade backup capabilities');
                }

                if (criteria.globalDistribution) {
                    score += 25;
                    reasoning.push('Global CDN integration');
                }
                break;
        }

        // Apply performance weighting
        if (criteria.performance === 'high' && performance.latency === 'low') {
            score += 15;
            reasoning.push('Matches high-performance requirements');
        }

        // Apply cost sensitivity
        if (criteria.costSensitivity === 'high' && estimatedCostPerGB < 0.05) {
            score += 10;
            reasoning.push('Cost-effective option');
        }

        return {
            provider,
            score,
            reasoning,
            estimatedCostPerGB,
            performance,
            compliance,
        };
    }
}