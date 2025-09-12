/**
 * Node.js path module mock
 * Provides mocked implementations for path operations
 */

export const join = jest.fn().mockImplementation((...paths: string[]) => {
    return paths.join('/');
});

export const dirname = jest.fn().mockImplementation((path: string) => {
    const parts = path.split('/');
    parts.pop();
    return parts.join('/') || '.';
});

export const basename = jest.fn().mockImplementation((path: string, ext?: string) => {
    const base = path.split('/').pop() || '';
    if (ext && base.endsWith(ext)) {
        return base.slice(0, -ext.length);
    }
    return base;
});

export const extname = jest.fn().mockImplementation((path: string) => {
    const base = basename(path);
    const dotIndex = base.lastIndexOf('.');
    return dotIndex > 0 ? base.slice(dotIndex) : '';
});

export const resolve = jest.fn().mockImplementation((...paths: string[]) => {
    return paths.join('/');
});

export default {
    join,
    dirname,
    basename,
    extname,
    resolve,
};