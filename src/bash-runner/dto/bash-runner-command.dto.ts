import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber, IsOptional, IsString } from 'class-validator';

export class BashRunnerCommandDto {
  @ApiProperty({
    description: 'The action to perform',
    example: 'docker-tagserver-run',
  })
  @IsString()
  @IsNotEmpty()
  action: string;

  @ApiProperty({
    description: 'Container ID',
    example: 'cmesvssw70001jxverncq9rx4',
  })
  @IsString()
  @IsOptional()
  containerId?: string;

  @ApiProperty({
    description: 'Container name',
    example: 'sgtm-cmesru0f-b75027ef',
    required: false,
  })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiProperty({ description: 'User ID', example: 'cmesru0fr0000jx5buw646i81' })
  @IsString()
  @IsNotEmpty()
  user: string;

  @ApiProperty({
    description: 'Subdomain',
    example: 'tags.bikobazaar.xyz',
    required: false,
  })
  @IsString()
  @IsOptional()
  subdomain?: string;

  @ApiProperty({
    description: 'Configuration data',
    example: 'aWQ9R1RNLVdGOFc4WER...',
    required: false,
  })
  @IsString()
  @IsOptional()
  config?: string;

  @ApiProperty({
    description: 'Number of lines for logs',
    example: 100,
    required: false,
  })
  @IsNumber()
  @IsOptional()
  lines?: number;

  @ApiProperty({
    description: 'Command ID for tracking',
    example: 'create-cmesvssw70001jxverncq9rx4-1756233027665',
  })
  @IsString()
  @IsOptional()
  commandId?: string;
}

export class DockerTagserverRunCommandDto extends BashRunnerCommandDto {
  @ApiProperty({
    description: 'The action to perform',
    example: 'docker-tagserver-run',
  })
  action: 'docker-tagserver-run';
}

export class DockerTagserverStopCommandDto extends BashRunnerCommandDto {
  @ApiProperty({
    description: 'The action to perform',
    example: 'docker-tagserver-stop',
  })
  action: 'docker-tagserver-stop';
}

export class DockerTagserverGetCommandDto extends BashRunnerCommandDto {
  @ApiProperty({
    description: 'The action to perform',
    example: 'docker-tagserver-get',
  })
  action: 'docker-tagserver-get';

  @ApiProperty({ description: 'Number of lines for logs', example: 100 })
  @IsNumber()
  @IsOptional()
  lines?: number;
}

export class DockerTagserverDeleteCommandDto extends BashRunnerCommandDto {
  @ApiProperty({
    description: 'The action to perform',
    example: 'docker-tagserver-delete',
  })
  action: 'docker-tagserver-delete';
}
