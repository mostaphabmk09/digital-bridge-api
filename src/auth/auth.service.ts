import { Injectable, BadRequestException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService, private jwtService: JwtService,private configService: ConfigService) {}

  async register(email:string,password:string) {
    const existingUser = await this.usersService.findByEmail(email);

    if (existingUser) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.usersService.create({
      email: email,
      password: hashedPassword,
    });

    return {
      message: 'User created successfully',
      userId: user.id,
    };
  }

   async login(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      user.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_ACCESS_SECRET'),
      expiresIn: this.configService.get('JWT_ACCESS_EXPIRES'),
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get('JWT_REFRESH_EXPIRES'),
    });

    // hash refresh token
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    await this.usersService.updateRefreshToken(
      user.id,
      hashedRefreshToken,
    );

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshFromToken(refreshToken: string) {
  const payload = await this.jwtService.verifyAsync(refreshToken, {
    secret: this.configService.get('JWT_REFRESH_SECRET'),
  });

  const user = await this.usersService.findById(payload.sub);

  if (!user || !user.refreshToken) {
    throw new UnauthorizedException('Access denied');
  }

  const isMatch = await bcrypt.compare(
    refreshToken,
    user.refreshToken,
  );

  if (!isMatch) {
    await this.usersService.updateRefreshToken(user.id, null);
    throw new UnauthorizedException('Invalid refresh token');
  }

  const newPayload = {
    sub: user.id,
    email: user.email,
    role: user.role,
  };

  const newAccessToken = await this.jwtService.signAsync(newPayload, {
    secret: this.configService.get('JWT_ACCESS_SECRET'),
    expiresIn: this.configService.get('JWT_ACCESS_EXPIRES'),
  });

  const newRefreshToken = await this.jwtService.signAsync(newPayload, {
    secret: this.configService.get('JWT_REFRESH_SECRET'),
    expiresIn: this.configService.get('JWT_REFRESH_EXPIRES'),
  });

  const hashedRefreshToken = await bcrypt.hash(newRefreshToken, 10);

  await this.usersService.updateRefreshToken(
    user.id,
    hashedRefreshToken,
  );

  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
  };
}
}