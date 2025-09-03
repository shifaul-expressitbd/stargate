// Jest mock for ImpersonationGuard to resolve import issues in tests
export const ImpersonationGuard = jest.fn().mockImplementation(() => ({
  canActivate: jest.fn().mockReturnValue(true),
}));
