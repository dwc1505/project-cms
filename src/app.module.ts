import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from './users/users.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { config } from 'process';
import { AuthModule } from './auth/auth.module';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './auth/passport/jwt-auth.guard';

@Module({
  imports: [
      MongooseModule.forRootAsync({
        imports: [ConfigModule],
        useFactory: async (configService: ConfigService) => ({
          uri: configService.get<string>('MONGODB_URI'),
        }),
        inject: [ConfigService],
      }),
      ConfigModule.forRoot({
        isGlobal: true,
      }),
      UsersModule,
      AuthModule,
  ],
  controllers: [AppController],
  providers: [AppService,
    {
    provide: APP_GUARD,
    useClass: JwtAuthGuard,
  },
  ],
})
export class AppModule {}
