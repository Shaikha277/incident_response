import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AuditLogModule } from 'src/audit-logs/audit-log.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/user.entity'
import { JwtStrategy } from './jwt.strategy';
import { PassportModule } from '@nestjs/passport';
@Module({
  imports: [
    ConfigModule,
    PassportModule,
    TypeOrmModule.forFeature([User]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get('JWT_SECRET'),
        signOptions: { expiresIn: config.get('JWT_EXPIRES_IN') },
      }),
    }),
    AuditLogModule,
  ],
  providers: [AuthService, JwtStrategy],
  exports: [AuthService , JwtStrategy,PassportModule],
  controllers: [AuthController],
})
export class AuthModule {}
