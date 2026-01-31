import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, Repository } from 'typeorm';
import { User, AuthProvider } from '../users/user.entity';
import { UnauthorizedException, ConflictException } from '@nestjs/common';
import { RegisterDto } from '../users/dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { AuditLogsService } from '../audit-logs/audit-log.service';
import { AuditAction } from '../audit-logs/enum/audit-action.enum';

interface JwtPayload {
  sub: string;
  email: string;
  role: string;
}

@Injectable()
export class AuthService {
  async register(dto: RegisterDto, ipAddress?: string, userAgent?: string) {
    const existingUser = await this.userRepository.findOne({
      where: [{ email: dto.email }, { username: dto.username }],
    });

    if (existingUser) {
      throw new ConflictException('Username/Email already exists');
    }

    const hashedPassword = await this.hashPassword(dto.password);

    const user = this.userRepository.create({
      email: dto.email,
      username: dto.username,
      firstName: dto.firstName,
      lastName: dto.lastName,
      password: hashedPassword,
      provider: AuthProvider.LOCAL,
    });

    const savedUser = await this.userRepository.save(user);

    await this.auditLogsService.log({
      userId: savedUser.id,
      action: AuditAction.USER_REGISTERED,
      status: 'success',
      ipAddress,
      userAgent,
      details: `User registered with email: ${dto.email}`,
    });

    const payload: JwtPayload = {
      sub: savedUser.id,
      email: savedUser.email,
      role: savedUser.role,
    };
    const token = this.createToken(payload);

    return {
      message: 'Registered successfully',
      access_token: token,
      user: this.sanitizeUser(savedUser),
    };
  }
  async login(dto: LoginDto, ipAddress?: string, userAgent?: string) {
    const { identifier, password } = dto;
    const user = await this.userRepository.findOne({
      where: [{ email: identifier }, { username: identifier }],
    });

    if (!user) {
      await this.auditLogsService.log({
        action: AuditAction.USER_LOGIN_FAILED,
        status: 'failure',
        ipAddress,
        userAgent,
        details: `Login attempt for non-existent user: ${identifier}`,
      });
      throw new UnauthorizedException('Invalid credentials');
    }
    if (user.isAccountLocked()) {
      await this.auditLogsService.log({
        userId: user.id,
        action: AuditAction.USER_LOGIN_FAILED,
        status: 'failure',
        ipAddress,
        userAgent,
        details: 'Login attempt on locked account',
      });
      throw new UnauthorizedException(
        'Account is locked. Please try again later.',
      );
    }

    if (user.provider !== AuthProvider.LOCAL || !user.password) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isMatch = await this.comparePassword(user.password, password);

    if (!isMatch) {
      user.loginAttempts += 1;
      const maxAttempts = this.configService.get<number>(
        'MAX_LOGIN_ATTEMPTS',
        5,);
      if (user.loginAttempts >= maxAttempts) {
        user.isLocked = true;
        const lockTime = this.configService.get<number>('LOCK_TIME', 900000);
        user.lockedUntil = new Date(Date.now() + lockTime);

        await this.auditLogsService.log({
          userId: user.id,
          action: AuditAction.ACCOUNT_LOCKED,
          status: 'success',
          ipAddress,
          userAgent,
          details: `Account locked after ${maxAttempts} failed attempts`,
        });
      }
        await this.userRepository.save(user);

        await this.auditLogsService.log({
          userId: user.id,
          action: AuditAction.USER_LOGIN_FAILED,
          status: 'failure',
          ipAddress,
          userAgent,
          details: `Invalid password (${user.loginAttempts}/${maxAttempts})`,
        });

      throw new UnauthorizedException('Invalid credentials');
    }
    user.loginAttempts = 0;
    user.isLocked = false;
    user.lockedUntil = null as any;
    await this.userRepository.save(user);

    await this.auditLogsService.log({
    userId: user.id,
    action: AuditAction.USER_LOGIN_SUCCESS,
    status: 'success',
    ipAddress,
    userAgent,
    details: 'User logged in successfully',
  });


    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    return {
      message: 'Logged in successfully',
      access_token: this.createToken(payload),
      user: this.sanitizeUser(user),
    };
  }

  private readonly saltRounds: number;

  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private auditLogsService: AuditLogsService,
  ) {
    this.saltRounds = Number(this.configService.get('SALT_ROUNDS', 12));
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }

  async comparePassword(
    storedPassword: string,
    password: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, storedPassword);
  }

  createToken(payload: JwtPayload): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_SECRET'),
      expiresIn: this.configService.get('JWT_EXPIRES_IN', '20m'),
    });
  }

  private sanitizeUser(user: User) {
    const { password, loginAttempts, lockedUntil, ...sanitized } = user;
    return sanitized;
  }
}
