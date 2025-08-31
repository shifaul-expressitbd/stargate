import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class UpdateGa4ConfigDto {
  @ApiProperty({ example: '12345678' })
  @IsString()
  @IsNotEmpty()
  accountId: string;

  @ApiProperty({ example: 'GTM-XXXXXX' })
  @IsString()
  @IsNotEmpty()
  containerId: string;

  @ApiProperty({ example: '20' })
  @IsString()
  @IsNotEmpty()
  workspaceId: string;

  @ApiProperty({ example: '15' })
  @IsString()
  @IsNotEmpty()
  ga4TagId: string;

  @ApiProperty({ example: 'https://container.example.com' })
  @IsString()
  @IsNotEmpty()
  serverContainerUrl: string;
}
