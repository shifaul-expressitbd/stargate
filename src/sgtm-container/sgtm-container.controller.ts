import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  UseGuards,
  Delete,
  Query,
} from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { User } from '../common/decorators/user.decorator';
import { ApiTags, ApiBearerAuth, ApiResponse, ApiBody } from '@nestjs/swagger';
import { SgtmContainerService } from './sgtm-container.service';
import { CreateSgtmContainerDto } from './dto/create-sgtm-container.dto';
import { RunSgtmContainerDto } from './dto/run-sgtm-container.dto';

@ApiTags('sGTM Containers')
@ApiBearerAuth('JWT-auth')
@UseGuards(JwtAuthGuard)
@Controller('sgtm-container')
export class SgtmContainerController {
  constructor(private readonly containerService: SgtmContainerService) {}

  @Post()
  async create(
    @User('id') userId: string,
    @Body() dto: CreateSgtmContainerDto,
  ) {
    return this.containerService.create(userId, dto);
  }

  @Get()
  async findAll(@User('id') userId: string) {
    return this.containerService.findAllByUser(userId);
  }

  @Get(':id')
  async findOne(@Param('id') id: string, @User('id') userId: string) {
    return this.containerService.findByIdAndUser(id, userId);
  }

  @Post(':id/run')
  async run(
    @Param('id') id: string,
    @User('id') userId: string,
    @Body() runDto: RunSgtmContainerDto,
  ) {
    return this.containerService.run(id, userId, runDto);
  }

  @Post(':id/stop')
  async stop(@Param('id') id: string, @User('id') userId: string) {
    return this.containerService.stop(id, userId);
  }

  @Get(':id/logs')
  async getLogs(
    @Param('id') id: string,
    @User('id') userId: string,
    @Query('lines') lines?: number,
  ) {
    return this.containerService.getLogs(id, userId, lines);
  }

  @Delete(':id')
  async remove(@Param('id') id: string, @User('id') userId: string) {
    return this.containerService.delete(id, userId);
  }
}