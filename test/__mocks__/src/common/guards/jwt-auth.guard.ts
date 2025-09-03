// Jest mock for JwtAuthGuard to resolve import issues in tests
export const JwtAuthGuard = jest.fn().mockImplementation(() => ({
  canActivate: jest.fn().mockReturnValue(true),
}));
