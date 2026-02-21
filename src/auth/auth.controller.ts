import { Controller, Post, Body, Res, Req, UnauthorizedException, UseGuards, Get } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import type { Response,Request } from 'express';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Public } from './public.decorator';


@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService,private usersService: UsersService, private jwtService: JwtService,private configService: ConfigService) {}

  @Post('register')
  @Public()
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto.email,dto.password);
  }

  @Post('login')
  @Public()
async login(
  @Body() dto: LoginDto,
  @Res({ passthrough: true }) res: Response,
) {
  const tokens = await this.authService.login(dto.email, dto.password);

  res.cookie('refreshToken', tokens.refreshToken, {
    httpOnly: true,
    secure: false, // true ف production مع https
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  return {
    accessToken: tokens.accessToken,
  };
}

  @Post('refresh')
  @Public()
async refresh(
  @Req() req: Request,
  @Res({ passthrough: true }) res: Response,
) {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    throw new UnauthorizedException('No refresh token');
  }

  const tokens = await this.authService.refreshFromToken(refreshToken);

  res.cookie('refreshToken', tokens.refreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  return {
    accessToken: tokens.accessToken,
  };
}

@Public()
@Post('logout')
async logout(
  @Req() req: Request,
  @Res({ passthrough: true }) res: Response,
) {
  const refreshToken = req.cookies?.refreshToken;

  if (refreshToken) {
    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      });

      await this.usersService.updateRefreshToken(payload.sub, null);
    } catch (err) {
      throw new UnauthorizedException('Access denied');
    }
  }

  res.clearCookie('refreshToken');

  return { message: 'Logged out successfully' };
}

@Get('profile')
@UseGuards(JwtAuthGuard)
getProfile(@Req() req) {
  return req.user;
}
}