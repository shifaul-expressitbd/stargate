export enum AuthProvider {
  LOCAL = 'LOCAL',
  GOOGLE = 'GOOGLE',
  FACEBOOK = 'FACEBOOK',
  GITHUB = 'GITHUB',
  TWITTER = 'TWITTER',
  LINKEDIN = 'LINKEDIN',
  MICROSOFT = 'MICROSOFT',
  APPLE = 'APPLE',
}

export const mapStringToProviderEnum = (provider: string): AuthProvider => {
  const providerMap: { [key: string]: AuthProvider } = {
    local: AuthProvider.LOCAL,
    google: AuthProvider.GOOGLE,
    facebook: AuthProvider.FACEBOOK,
    github: AuthProvider.GITHUB,
    twitter: AuthProvider.TWITTER,
    linkedin: AuthProvider.LINKEDIN,
    microsoft: AuthProvider.MICROSOFT,
    apple: AuthProvider.APPLE,
  };

  const enumValue = providerMap[provider.toLowerCase()];
  if (!enumValue) {
    throw new Error(`Unsupported provider: ${provider}`);
  }

  return enumValue;
};
