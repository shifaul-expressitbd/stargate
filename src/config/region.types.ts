// src/config/region.types.ts
export type RegionKey = 'india' | 'us-east' | 'us-west' | 'europe';

export interface RegionConfig {
  name: string;
  apiUrl?: string;
  apiKey?: string;
  default?: boolean;
}

export interface RunnerRegionConfig {
  [key: string]: RegionConfig;
}

export interface RunnerConfig {
  // Legacy configuration for backward compatibility
  apiUrl?: string;
  apiKey?: string;

  // Region-based configuration
  regions: RunnerRegionConfig;
  defaultRegion: RegionKey;
}

export const SUPPORTED_REGIONS: RegionKey[] = [
  'india',
  'us-east',
  'us-west',
  'europe',
];

export const DEFAULT_REGION: RegionKey = 'india';

export function isValidRegion(region: string): region is RegionKey {
  return SUPPORTED_REGIONS.includes(region as RegionKey);
}

export function getRegionConfig(
  regions: RunnerRegionConfig,
  region: RegionKey,
): RegionConfig | null {
  return regions[region] || null;
}

export function getDefaultRegionConfig(
  regions: RunnerRegionConfig,
): RegionConfig | null {
  const defaultRegion = Object.values(regions).find((region) => region.default);
  return defaultRegion || regions[DEFAULT_REGION] || null;
}
