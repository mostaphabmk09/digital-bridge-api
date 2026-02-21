import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { GetCurrentUser } from './GetCurrentUser.decorator';

@Controller('users')
export class UsersController {

  @Get('me')
  getMe(@GetCurrentUser() user: Express.User) {
    return user;
  }
}