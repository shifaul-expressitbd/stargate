/**
 * Abstract Storage Service Tests
 * Tests the base functionality and common methods of all storage services
 */

import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { MulterFile } from '../../interfaces/file-options.interface';
import { LocalStorageOptions } from '../../interfaces/storage-options.interface';
import { StorageProvider } from '../../interfaces/storage.interface';
import { AbstractStorageService } from '../abstract-storage.service';

// Mock ConfigService
const mockConfigService = {
    get: jest.fn(),
};

// Create a concrete implementation for testing
class TestStorageService extends AbstractStorageService {
    constructor(options: LocalStorageOptions, configService: ConfigService) {
        super(StorageProvider.LOCAL, options, configService);
    }

    async upload(
        file: MulterFile | Buffer,
        key?: string,
        options?: any
    ): Promise<any> {
        return {
            fileId: 'test-file-id',
            key: key || 'test-key',
            url: 'http://localhost:3000/test-file',
            metadata: {
                size: 1024,
                mimeType: 'application/octet-stream',
                filename: 'test-file',
                uploadedAt: new Date(),
            },
            success: true,
        };
    }

    async download(key: string): Promise<any> {
        return {
            stream: { pipe: jest.fn() },
            metadata: {
                size: 1024,
                mimeType: 'application/octet-stream',
                lastModified: new Date(),
            },
            success: true,
        };
    }

    async delete(key: string): Promise<any> {
        return { success: true };
    }

    async exists(key: string): Promise<any> {
        return { exists: true };
    }

    async getUrl(key: string, options?: any): Promise<any> {
        return {
            url: `http://localhost:3000/files/${key}`,
            success: true,
        };
    }

    async copy(fromKey: string, toKey: string): Promise<any> {
        return { success: true };
    }

    protected async performHealthCheck(): Promise<boolean> {
        return true;
    }
}

describe('AbstractStorageService', () => {
    let service: TestStorageService;
    let configService: ConfigService;

    const mockOptions: LocalStorageOptions = {
        provider: StorageProvider.LOCAL,
        baseDir: '/tmp/uploads',
        createDirs: true,
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
                {
                    provide: TestStorageService,
                    useFactory: (configService: ConfigService) =>
                        new TestStorageService(mockOptions, configService),
                    inject: [ConfigService],
                },
            ],
        }).compile();

        service = module.get<TestStorageService>(TestStorageService);
        configService = module.get<ConfigService>(ConfigService);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Initialization', () => {
        it('should be defined', () => {
            expect(service).toBeDefined();
        });

        it('should have correct provider', () => {
            expect(service['provider']).toBe(StorageProvider.LOCAL);
        });

        it('should have correct options', () => {
            expect(service['options']).toBe(mockOptions);
        });
    });

    describe('Key Generation', () => {
        it('should generate key for MulterFile', () => {
            const file: MulterFile = {
                fieldname: 'file',
                originalname: 'test.pdf',
                encoding: '7bit',
                mimetype: 'application/pdf',
                size: 1024,
                destination: '/tmp',
                filename: 'test.pdf',
                path: '/tmp/test.pdf',
                buffer: Buffer.from('test content'),
            };

            const key = service.generateKey(file);

            expect(key).toContain('test');
            expect(key).toContain('.pdf');
        });

        it('should generate key for file object', () => {
            const file = {
                originalname: 'test.pdf',
                mimetype: 'application/pdf',
            };

            const key = service.generateKey(file);

            expect(key).toContain('test');
            expect(key).toContain('.pdf');
        });

        it('should preserve original name when specified', () => {
            const file: MulterFile = {
                fieldname: 'file',
                originalname: 'test.pdf',
                encoding: '7bit',
                mimetype: 'application/pdf',
                size: 1024,
                destination: '/tmp',
                filename: 'test.pdf',
                path: '/tmp/test.pdf',
                buffer: Buffer.from('test content'),
            };

            const key = service.generateKey(file, { preserveOriginalName: true });

            expect(key).toBe('test.pdf');
        });

        it('should add prefix when specified', () => {
            const file: MulterFile = {
                fieldname: 'file',
                originalname: 'test.pdf',
                encoding: '7bit',
                mimetype: 'application/pdf',
                size: 1024,
                destination: '/tmp',
                filename: 'test.pdf',
                path: '/tmp/test.pdf',
                buffer: Buffer.from('test content'),
            };

            const key = service.generateKey(file, { prefix: 'uploads/' });

            expect(key).toBe('uploads/test.pdf');
        });
    });

    describe('Capabilities', () => {
        it('should return default capabilities', () => {
            const capabilities = service.getCapabilities();

            expect(capabilities).toEqual({
                resumableUpload: false,
                signedUrls: false,
                cdnIntegration: false,
                versioning: false,
                customMetadata: false,
            });
        });
    });

    describe('Health Check', () => {
        it('should perform health check successfully', async () => {
            const result = await service.checkHealth();

            expect(result).toEqual({
                healthy: true,
                responseTime: expect.any(Number),
            });
        });

        it('should handle health check failure', async () => {
            // Mock health check failure
            const originalPerformHealthCheck = service['performHealthCheck'];
            service['performHealthCheck'] = jest.fn().mockRejectedValue(new Error('Health check failed'));

            const result = await service.checkHealth();

            expect(result).toEqual({
                healthy: false,
                responseTime: expect.any(Number),
                error: 'Health check failed',
            });

            // Restore original method
            service['performHealthCheck'] = originalPerformHealthCheck;
        });
    });

    describe('Error Handling', () => {
        it('should handle NotFoundException', () => {
            const error = { name: 'NotFoundException', message: 'File not found' };

            expect(() => {
                service['handleError'](error, 'test operation');
            }).toThrow('File not found');
        });

        it('should handle ENOENT error', () => {
            const error = { code: 'ENOENT', message: 'File not found' };

            expect(() => {
                service['handleError'](error, 'test operation');
            }).toThrow('File not found during test operation');
        });

        it('should handle permission error', () => {
            const error = { code: 'EACCES', message: 'Permission denied' };

            expect(() => {
                service['handleError'](error, 'test operation');
            }).toThrow('Permission denied during test operation');
        });

        it('should handle generic error', () => {
            const error = { message: 'Generic error' };

            expect(() => {
                service['handleError'](error, 'test operation');
            }).toThrow('Storage operation \'test operation\' failed: Generic error');
        });
    });

    describe('File Validation', () => {
        it('should validate file size', () => {
            const file: MulterFile = {
                fieldname: 'file',
                originalname: 'test.pdf',
                encoding: '7bit',
                mimetype: 'application/pdf',
                size: 2048,
                destination: '/tmp',
                filename: 'test.pdf',
                path: '/tmp/test.pdf',
                buffer: Buffer.from('test content'),
            };

            expect(() => {
                service['validateFile'](file, { maxSize: 1024 });
            }).toThrow('File size exceeds maximum allowed size of 1024 bytes');
        });

        it('should validate file type', () => {
            const file: MulterFile = {
                fieldname: 'file',
                originalname: 'test.exe',
                encoding: '7bit',
                mimetype: 'application/x-msdownload',
                size: 1024,
                destination: '/tmp',
                filename: 'test.exe',
                path: '/tmp/test.exe',
                buffer: Buffer.from('test content'),
            };

            expect(() => {
                service['validateFile'](file, {
                    allowedTypes: ['image/jpeg', 'application/pdf']
                });
            }).toThrow('File type application/x-msdownload is not allowed');
        });

        it('should pass validation with valid file', () => {
            const file: MulterFile = {
                fieldname: 'file',
                originalname: 'test.pdf',
                encoding: '7bit',
                mimetype: 'application/pdf',
                size: 1024,
                destination: '/tmp',
                filename: 'test.pdf',
                path: '/tmp/test.pdf',
                buffer: Buffer.from('test content'),
            };

            expect(() => {
                service['validateFile'](file, {
                    maxSize: 2048,
                    allowedTypes: ['application/pdf']
                });
            }).not.toThrow();
        });
    });

    describe('Retry Logic', () => {
        it('should retry operation on failure', async () => {
            const mockOperation = jest.fn()
                .mockRejectedValueOnce(new Error('First attempt failed'))
                .mockResolvedValueOnce('Success');

            const result = await service['withRetry'](mockOperation, 'test operation', 3, 10);

            expect(result).toBe('Success');
            expect(mockOperation).toHaveBeenCalledTimes(2);
        });

        it('should fail after max attempts', async () => {
            const mockOperation = jest.fn().mockRejectedValue(new Error('Always fails'));

            await expect(
                service['withRetry'](mockOperation, 'test operation', 2, 10)
            ).rejects.toThrow('Always fails');

            expect(mockOperation).toHaveBeenCalledTimes(2);
        });
    });

    describe('Move Operation', () => {
        it('should move file successfully', async () => {
            const result = await service.move('source-key', 'dest-key');

            expect(result).toEqual({ success: true });
        });

        it('should handle copy failure during move', async () => {
            // Mock copy to fail
            const originalCopy = service.copy;
            service.copy = jest.fn().mockResolvedValue({ success: false, error: 'Copy failed' });

            const result = await service.move('source-key', 'dest-key');

            expect(result).toEqual({
                success: false,
                error: 'Copy failed',
            });

            // Restore original method
            service.copy = originalCopy;
        });
    });

    describe('Default Implementations', () => {
        it('should return empty list by default', async () => {
            const result = await service.list();

            expect(result).toEqual({
                files: [],
                truncated: false,
            });
        });

        it('should return null for metadata by default', async () => {
            const result = await service.getMetadata('test-key');

            expect(result).toBeNull();
        });

        it('should return success false for metadata update by default', async () => {
            const result = await service.updateMetadata('test-key', {});

            expect(result).toEqual({
                success: false,
                error: 'Metadata updates not supported by this storage provider',
            });
        });
    });

    describe('Utility Methods', () => {
        it('should generate file ID', () => {
            const id = service['generateFileId']();

            expect(typeof id).toBe('string');
            expect(id.length).toBeGreaterThan(0);
        });

        it('should get MIME type from path', () => {
            expect(service['getMimeType']('test.pdf')).toBe('application/pdf');
            expect(service['getMimeType']('test.jpg')).toBe('image/jpeg');
            expect(service['getMimeType']('test.unknown')).toBe('application/octet-stream');
        });
    });
});