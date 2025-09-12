/**
 * Prisma Client Mock
 * Provides mocked implementations for Prisma database operations
 */

const mockFileMetadata = {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    findMany: jest.fn(),
    count: jest.fn(),
    aggregate: jest.fn(),
};

// Mock implementations
mockFileMetadata.create.mockResolvedValue({
    id: 'test-file-id',
    filename: 'test-file.pdf',
    originalName: 'original-test-file.pdf',
    mimeType: 'application/pdf',
    size: 1024000,
    path: 'uploads/test-file.pdf',
    storageProvider: 'local',
    storageKey: 'test-file-key',
    storageUrl: 'http://localhost:3000/files/test-file.pdf',
    category: 'document',
    createdAt: new Date(),
    updatedAt: new Date(),
});

mockFileMetadata.findUnique.mockResolvedValue({
    id: 'test-file-id',
    filename: 'test-file.pdf',
    originalName: 'original-test-file.pdf',
    mimeType: 'application/pdf',
    size: 1024000,
    path: 'uploads/test-file.pdf',
    storageProvider: 'local',
    storageKey: 'test-file-key',
    storageUrl: 'http://localhost:3000/files/test-file.pdf',
    category: 'document',
    createdAt: new Date(),
    updatedAt: new Date(),
});

mockFileMetadata.update.mockResolvedValue({
    id: 'test-file-id',
    filename: 'test-file.pdf',
    originalName: 'updated-test-file.pdf',
    mimeType: 'application/pdf',
    size: 1024000,
    path: 'uploads/test-file.pdf',
    storageProvider: 'local',
    storageKey: 'test-file-key',
    storageUrl: 'http://localhost:3000/files/test-file.pdf',
    category: 'document',
    createdAt: new Date(),
    updatedAt: new Date(),
});

mockFileMetadata.delete.mockResolvedValue({
    id: 'test-file-id',
    filename: 'test-file.pdf',
    originalName: 'original-test-file.pdf',
    mimeType: 'application/pdf',
    size: 1024000,
    path: 'uploads/test-file.pdf',
    storageProvider: 'local',
    storageKey: 'test-file-key',
    storageUrl: 'http://localhost:3000/files/test-file.pdf',
    category: 'document',
    createdAt: new Date(),
    updatedAt: new Date(),
});

mockFileMetadata.findMany.mockResolvedValue([
    {
        id: 'test-file-id-1',
        filename: 'test-file-1.pdf',
        originalName: 'original-test-file-1.pdf',
        mimeType: 'application/pdf',
        size: 1024000,
        path: 'uploads/test-file-1.pdf',
        storageProvider: 'local',
        storageKey: 'test-file-key-1',
        storageUrl: 'http://localhost:3000/files/test-file-1.pdf',
        category: 'document',
        createdAt: new Date(),
        updatedAt: new Date(),
    },
    {
        id: 'test-file-id-2',
        filename: 'test-file-2.jpg',
        originalName: 'original-test-file-2.jpg',
        mimeType: 'image/jpeg',
        size: 512000,
        path: 'uploads/test-file-2.jpg',
        storageProvider: 'cloudinary',
        storageKey: 'test-file-key-2',
        storageUrl: 'https://res.cloudinary.com/test/image/upload/test-file-2.jpg',
        category: 'image',
        createdAt: new Date(),
        updatedAt: new Date(),
    },
]);

mockFileMetadata.count.mockResolvedValue(2);

mockFileMetadata.aggregate.mockResolvedValue({
    _count: { id: 2 },
    _sum: { size: 1536000 },
});

const mockPrismaClient = {
    fileMetadata: mockFileMetadata,
};

// Mock the PrismaService
export const PrismaService = jest.fn().mockImplementation(() => mockPrismaClient);

// Export as default for mocking
export default mockPrismaClient;
