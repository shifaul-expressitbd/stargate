import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsOptional } from 'class-validator';

export class RunSgtmContainerDto {
  @ApiProperty({ example: 'run', required: false, default: 'run' })
  @IsString()
  @IsOptional()
  action?: 'run' | 'restart' | 'update';

  @ApiProperty({ example: 'tags.bikobazaar.xyz', required: false })
  @IsString()
  @IsOptional()
  subdomain?: string;

  @ApiProperty({ example: 'aWQ9R1RNLUtCODJMNzRO...', required: false })
  @IsString()
  @IsOptional()
  config?: string;

  @ApiProperty({ example: { NODE_ENV: 'staging' }, required: false })
  @IsOptional()
  env?: Record<string, string>;
}
