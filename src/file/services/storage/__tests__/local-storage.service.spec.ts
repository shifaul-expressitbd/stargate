/**
 * Local Storage Service Tests
 * Tests the local file system storage implementation
 */

import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { MulterFile } from '../../../interfaces/file-options.interface';
import { LocalStorageOptions } from '../../../interfaces/storage-options.interface';
import { StorageProvider } from '../../../interfaces/storage.interface';
import { LocalStorageService } from '../local-storage.service';

// Mock external dependencies
jest.mock('fs', () => ({
    promises: {
        writeFile: jest.fn(),
        readFile: jest.fn(),
        stat: jest.fn(),
        mkdir: jest.fn(),
        unlink: jest.fn(),
        access: jest.fn(),
        copyFile: jest.fn(),
        rename: jest.fn(),
        readdir: jest.fn(),
        rmdir: jest.fn(),
    },
    createReadStream: jest.fn(),
    constants: {
        F_OK: 0,
        W_OK: 2,
    },
}));

jest.mock('path', () => ({
    join: jest.fn(),
    dirname: jest.fn(),
    basename: jest.fn(),
    extname: jest.fn(),
}));

jest.mock('crypto', () => ({
    randomUUID: jest.fn(),
    randomBytes: jest.fn(),
}));

const mockFs = require('fs');
const mockPath = require('path');
const mockCrypto = require('crypto');

// Mock ConfigService
const mockConfigService = {
    get: jest.fn(),
};

describe('LocalStorageService', () => {
    let service: LocalStorageService;
    let configService: ConfigService;

    const mockOptions: LocalStorageOptions = {
        provider: StorageProvider.LOCAL,
        baseDir: '/tmp/uploads',
        createDirs: true,
        permissions: 0o755,
    };

    const mockMulterFile: MulterFile = {
        fieldname: 'file',
        originalname: 'test.pdf',
        encoding: '7bit',
        mimetype: 'application/pdf',
        size: 1024000,
        destination: '/tmp',
        filename: 'test.pdf',
        path: '/tmp/test.pdf',
        buffer: Buffer.from('test file content'),
    };

    const mockBuffer = Buffer.from('test buffer content');

    beforeEach(async () => {
        // Reset all mocks
        jest.clearAllMocks();

        // Setup default mock implementations
        mockPath.join.mockImplementation((...args) => args.join('/'));
        mockPath.dirname.mockImplementation((p) => p.split('/').slice(0, -1).join('/') || '.');
        mockPath.basename.mockImplementation((p) => p.split('/').pop() || '');
        mockPath.extname.mockImplementation((p) => {
            const base = mockPath.basename(p);
            const dotIndex = base.lastIndexOf('.');
            return dotIndex > 0 ? base.slice(dotIndex) : '';
        });

        mockFs.promises.writeFile.mockResolvedValue(undefined);
        mockFs.promises.readFile.mockResolvedValue(mockBuffer);
        mockFs.promises.stat.mockResolvedValue({
            size: 1024000,
            mtime: new Date(),
            ctime: new Date(),
            birthtime: new Date(),
            isFile: () => true,
            isDirectory: () => false,
        } as any);
        mockFs.promises.mkdir.mockResolvedValue(undefined);
        mockFs.promises.unlink.mockResolvedValue(undefined);
        mockFs.promises.access.mockResolvedValue(undefined);
        mockFs.promises.copyFile.mockResolvedValue(undefined);
        mockFs.promises.rename.mockResolvedValue(undefined);
        mockFs.promises.readdir.mockResolvedValue(['file1.txt', 'file2.jpg']);
        mockFs.createReadStream.mockReturnValue({
            pipe: jest.fn(),
            on: jest.fn(),
            destroy: jest.fn(),
        } as any);

        mockCrypto.randomUUID.mockReturnValue('123e4567-e89b-12d3-a456-426614174000');
        mockCrypto.randomBytes.mockReturnValue({
            toString: jest.fn().mockReturnValue('mock-random-bytes'),
        });

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
                {
                    provide: LocalStorageService,
                    useFactory: (configService: ConfigService) =>
                        new LocalStorageService(mockOptions, configService),
                    inject: [ConfigService],
                },
            ],
        }).compile();

        service = module.get<LocalStorageService>(LocalStorageService);
        configService = module.get<ConfigService>(ConfigService);
    });

    describe('Initialization', () => {
        it('should be defined', () => {
            expect(service).toBeDefined();
        });

        it('should have correct provider', () => {
            expect(service['provider']).toBe(StorageProvider.LOCAL);
        });

        it('should have correct options', () => {
            expect(service['fileConfig']).toBe(mockOptions);
        });
    });

    describe('Upload Operations', () => {
        describe('Buffer Upload', () => {
            it('should upload buffer successfully', async () => {
                const result = await service.upload(mockBuffer, 'test-key');

                expect(result).toEqual({
                    fileId: '123e4567-e89b-12d3-a456-426614174000',
                    key: 'test-key',
                    url: 'http://localhost:3000/files/test-key',
                    metadata: {
                        size: 1024000,
                        mimeType: 'application/pdf',
                        filename: 'test-key',
                        uploadedAt: expect.any(Date),
                    },
                    success: true,
                });

                expect(mockFs.promises.mkdir).toHaveBeenCalledWith('/tmp/uploads', { recursive: true });
                expect(mockFs.promises.writeFile).toHaveBeenCalledWith('/tmp/uploads/test-key', mockBuffer);
            });

            it('should generate key for buffer upload', async () => {
                const result = await service.upload(mockBuffer);

                expect(result.key).toBe('buffer_1234567890000_mock-random-bytes');
                expect(mockCrypto.randomBytes).toHaveBeenCalledWith(4);
            });
        });

        describe('MulterFile Upload', () => {
            it('should upload MulterFile successfully', async () => {
                const result = await service.upload(mockMulterFile, 'custom-key');

                expect(result).toEqual({
                    fileId: '123e4567-e89b-12d3-a456-426614174000',
                    key: 'custom-key',
                    url: 'http://localhost:3000/files/custom-key',
                    metadata: {
                        size: 1024000,
                        mimeType: 'application/pdf',
                        filename: 'custom-key',
                        uploadedAt: expect.any(Date),
                    },
                    success: true,
                });

                expect(mockFs.promises.rename).toHaveBeenCalledWith('/tmp/test.pdf', '/tmp/uploads/custom-key');
            });

            it('should handle cross-device rename error', async () => {
                mockFs.promises.rename.mockRejectedValue({ code: 'EXDEV' });

                const result = await service.upload(mockMulterFile, 'test-key');

                expect(mockFs.promises.copyFile).toHaveBeenCalledWith('/tmp/test.pdf', '/tmp/uploads/test-key');
                expect(mockFs.promises.unlink).toHaveBeenCalledWith('/tmp/test.pdf');
            });
        });

        it('should handle upload errors', async () => {
            mockFs.promises.writeFile.mockRejectedValue(new Error('Write failed'));

            const result = await service.upload(mockBuffer, 'test-key');

            expect(result).toEqual({
                fileId: '',
                key: '',
                url: '',
                metadata: {
                    size: 0,
                    mimeType: '',
                    filename: '',
                    uploadedAt: expect.any(Date),
                },
                success: false,
                error: 'Write failed',
            });
        });

        it('should create directories when createDirs is true', async () => {
            const result = await service.upload(mockBuffer, 'nested/path/test-key');

            expect(mockFs.promises.mkdir).toHaveBeenCalledWith('/tmp/uploads/nested/path', { recursive: true });
        });
    });

    describe('Download Operations', () => {
        it('should download file successfully', async () => {
            const result = await service.download('test-key');

            expect(result).toEqual({
                stream: expect.any(Object),
                metadata: {
                    size: 1024000,
                    mimeType: 'application/pdf',
                    lastModified: expect.any(Date),
                },
                success: true,
            });

            expect(mockFs.createReadStream).toHaveBeenCalledWith('/tmp/uploads/test-key', {
                highWaterMark: 65536, // 64KB
            });
        });

        it('should handle file not found', async () => {
            mockFs.promises.access.mockRejectedValue({ code: 'ENOENT' });

            await expect(service.download('nonexistent-key')).rejects.toThrow('File not found');
        });

        it('should handle download errors', async () => {
            mockFs.createReadStream.mockImplementation(() => {
                throw new Error('Stream creation failed');
            });

            const result = await service.download('test-key');

            expect(result).toEqual({
                success: false,
                error: 'Stream creation failed',
            });
        });
    });

    describe('Delete Operations', () => {
        it('should delete file successfully', async () => {
            const result = await service.delete('test-key');

            expect(result).toEqual({ success: true });
            expect(mockFs.promises.unlink).toHaveBeenCalledWith('/tmp/uploads/test-key');
        });

        it('should handle file not found during deletion', async () => {
            mockFs.promises.access.mockRejectedValue({ code: 'ENOENT' });

            const result = await service.delete('nonexistent-key');

            expect(result).toEqual({
                success: false,
                error: 'File not found',
            });
        });

        it('should cleanup empty directories', async () => {
            mockFs.promises.readdir.mockResolvedValue([]); // Empty directory

            await service.delete('nested/path/test-key');

            expect(mockFs.promises.rmdir).toHaveBeenCalledWith('/tmp/uploads/nested/path');
            expect(mockFs.promises.rmdir).toHaveBeenCalledWith('/tmp/uploads/nested');
        });

        it('should not cleanup non-empty directories', async () => {
            mockFs.promises.readdir.mockResolvedValue(['other-file.txt']); // Non-empty directory

            await service.delete('nested/path/test-key');

            expect(mockFs.promises.rmdir).not.toHaveBeenCalled();
        });

        it('should handle deletion errors', async () => {
            mockFs.promises.unlink.mockRejectedValue(new Error('Delete failed'));

            const result = await service.delete('test-key');

            expect(result).toEqual({
                success: false,
                error: 'Delete failed',
            });
        });
    });

    describe('Exists Operations', () => {
        it('should check file existence successfully', async () => {
            const result = await service.exists('test-key');

            expect(result).toEqual({
                exists: true,
                metadata: {
                    size: 1024000,
                    mimeType: 'application/pdf',
                    lastModified: expect.any(Date),
                },
            });
        });

        it('should handle file not found', async () => {
            mockFs.promises.access.mockRejectedValue({ code: 'ENOENT' });

            const result = await service.exists('nonexistent-key');

            expect(result).toEqual({ exists: false });
        });
    });

    describe('URL Generation', () => {
        it('should generate URL without options', async () => {
            const result = await service.getUrl('test-key');

            expect(result).toEqual({
                url: 'http://localhost:3000/files/test-key',
                success: true,
            });
        });

        it('should handle URL generation errors', async () => {
            const result = await service.getUrl('test-key', { expiresIn: 3600 });

            // Local storage doesn't support signed URLs, so it should still return basic URL
            expect(result).toEqual({
                url: 'http://localhost:3000/files/test-key',
                success: true,
            });
        });
    });

    describe('Copy Operations', () => {
        it('should copy file successfully', async () => {
            const result = await service.copy('source-key', 'dest-key');

            expect(result).toEqual({ success: true });
            expect(mockFs.promises.copyFile).toHaveBeenCalledWith('/tmp/uploads/source-key', '/tmp/uploads/dest-key');
        });

        it('should create destination directory', async () => {
            await service.copy('source-key', 'nested/dest-key');

            expect(mockFs.promises.mkdir).toHaveBeenCalledWith('/tmp/uploads/nested', { recursive: true });
        });

        it('should handle source file not found', async () => {
            mockFs.promises.access.mockRejectedValue({ code: 'ENOENT' });

            const result = await service.copy('nonexistent-key', 'dest-key');

            expect(result).toEqual({
                success: false,
                error: 'Source file not found',
            });
        });
    });

    describe('List Operations', () => {
        it('should list files successfully', async () => {
            mockFs.promises.readdir.mockResolvedValue([
                { name: 'file1.txt', isFile: () => true, isDirectory: () => false },
                { name: 'file2.jpg', isFile: () => true, isDirectory: () => false },
                { name: 'subdir', isFile: () => false, isDirectory: () => true },
            ] as any);

            const result = await service.list('test-prefix');

            expect(result).toEqual({
                files: [
                    {
                        key: 'test-prefix/file1.txt',
                        size: 1024000,
                        lastModified: expect.any(Date),
                        mimeType: 'application/pdf',
                    },
                    {
                        key: 'test-prefix/file2.jpg',
                        size: 1024000,
                        lastModified: expect.any(Date),
                        mimeType: 'image/jpeg',
                    },
                ],
                truncated: false,
            });
        });

        it('should list files in root directory', async () => {
            const result = await service.list();

            expect(result.files[0].key).toBe('file1.txt');
            expect(result.files[1].key).toBe('file2.jpg');
        });

        it('should handle list errors', async () => {
            mockFs.promises.readdir.mockRejectedValue(new Error('List failed'));

            const result = await service.list();

            expect(result).toEqual({
                files: [],
                truncated: false,
            });
        });
    });

    describe('Metadata Operations', () => {
        it('should get file metadata', async () => {
            const result = await service.getMetadata('test-key');

            expect(result).toEqual({
                size: 1024000,
                mimeType: 'application/pdf',
                lastModified: expect.any(Date),
                etag: expect.stringContaining('"'),
            });
        });

        it('should return null for nonexistent file', async () => {
            mockFs.promises.access.mockRejectedValue({ code: 'ENOENT' });

            const result = await service.getMetadata('nonexistent-key');

            expect(result).toBeNull();
        });
    });

    describe('Health Check', () => {
        it('should return healthy when directory is writable', async () => {
            const result = await service['performHealthCheck']();

            expect(result).toBe(true);
            expect(mockFs.promises.access).toHaveBeenCalledWith('/tmp/uploads', mockFs.constants.W_OK);
        });

        it('should return unhealthy when directory is not accessible', async () => {
            mockFs.promises.access.mockRejectedValue(new Error('Access denied'));

            const result = await service['performHealthCheck']();

            expect(result).toBe(false);
        });
    });

    describe('Capabilities', () => {
        it('should return local storage capabilities', () => {
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

    describe('Utility Methods', () => {
        it('should generate file key for buffer', () => {
            const key = service['generateFileKey'](mockBuffer);

            expect(key).toBe('buffer_1234567890000_mock-random-bytes');
        });

        it('should generate file key for MulterFile', () => {
            const key = service['generateFileKey'](mockMulterFile);

            expect(key).toContain('test.pdf');
        });

        it('should get full path', () => {
            const fullPath = service['getFullPath']('test-key');

            expect(fullPath).toBe('/tmp/uploads/test-key');
        });

        it('should generate local URL', () => {
            const url = service['generateLocalUrl']('test-key');

            expect(url).toBe('http://localhost:3000/files/test-key');
        });

        it('should extract filename', () => {
            expect(service['extractFilename']('path/to/file.txt')).toBe('file.txt');
            expect(service['extractFilename']('file.txt')).toBe('file.txt');
        });

        it('should check file existence', async () => {
            const exists = await service['fileExists']('/tmp/test.txt');

            expect(exists).toBe(true);
            expect(mockFs.promises.access).toHaveBeenCalledWith('/tmp/test.txt', mockFs.constants.F_OK);
        });

        it('should ensure directory exists', async () => {
            await service['ensureDirectoryExists']('/tmp/new-dir');

            expect(mockFs.promises.mkdir).toHaveBeenCalledWith('/tmp/new-dir', { recursive: true });
        });
    });
});