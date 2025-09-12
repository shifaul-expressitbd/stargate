import { HttpModule } from '@nestjs/axios';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { LoggerService } from 'src/utils/logger/logger.service';
import { PrismaService } from '../database/prisma/prisma.service';
import { FileModule } from '../file/file.module';
import { SupportTicketsController } from './support-tickets.controller';
import { SupportTicketsService } from './support-tickets.service';

@Module({
    imports: [
        ConfigModule,
        FileModule,
        HttpModule,
        JwtModule.registerAsync({
            imports: [ConfigModule],
            useFactory: (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_SECRET'),
                signOptions: { expiresIn: '24h' },
            }),
            inject: [ConfigService],
        }),
    ],
    controllers: [SupportTicketsController],
    providers: [SupportTicketsService, PrismaService, LoggerService],
    exports: [SupportTicketsService],
})
export class SupportTicketsModule { }