/**
 * Node.js fs module mock
 * Provides mocked implementations for file system operations
 */

export const promises = {
    writeFile: jest.fn().mockResolvedValue(undefined),
    readFile: jest.fn().mockResolvedValue(Buffer.from('mock file content')),
    unlink: jest.fn().mockResolvedValue(undefined),
    stat: jest.fn().mockResolvedValue({
        size: 1024000,
        mtime: new Date(),
        ctime: new Date(),
        birthtime: new Date(),
        isFile: () => true,
        isDirectory: () => false,
    }),
    mkdir: jest.fn().mockResolvedValue(undefined),
    readdir: jest.fn().mockResolvedValue(['file1.txt', 'file2.jpg']),
    access: jest.fn().mockResolvedValue(undefined),
    copyFile: jest.fn().mockResolvedValue(undefined),
    rename: jest.fn().mockResolvedValue(undefined),
    rmdir: jest.fn().mockResolvedValue(undefined),
};

export const createReadStream = jest.fn().mockReturnValue({
    pipe: jest.fn(),
    on: jest.fn(),
    destroy: jest.fn(),
});

export const constants = {
    F_OK: 0,
    R_OK: 4,
    W_OK: 2,
    X_OK: 1,
};

export const existsSync = jest.fn().mockReturnValue(true);

export default {
    promises,
    createReadStream,
    constants,
    existsSync,
};