import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  ApiBody,
  ApiCookieAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { Throttle } from '@nestjs/throttler';
import { UserResponseType } from 'src/users/types/user-response.type';
import { Public } from 'src/decorators/public.decorator';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  @Public()
  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @ApiOperation({ summary: 'Login user' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: 200, description: 'Successful login' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{
    accessToken: string;
  }> {
    const { accessToken, refreshToken } =
      await this.authService.login(loginDto);

    this.setRefreshTokenCookie(res, refreshToken);
    return { accessToken };
  }

  @Public()
  @Post('register')
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @ApiOperation({ summary: 'Register user' })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({ status: 201, description: 'Successful registration' })
  @ApiResponse({ status: 400, description: 'Invalid input' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  async register(@Body() registerDto: RegisterDto): Promise<{
    message: string;
  }> {
    return this.authService.register(registerDto);
  }

  @Get('me/:token')
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiOperation({ summary: 'Get current user' })
  @ApiResponse({ status: 200, description: 'Successful request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  async me(@Param('token') token: string): Promise<UserResponseType> {
    return this.authService.getCurrentUser(token);
  }

  @Public()
  @Post('refresh-token')
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiCookieAuth('refreshToken')
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ status: 200, description: 'Successful token refresh' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  async refreshToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{
    accessToken: string;
  }> {
    const token = req.cookies?.refreshToken;
    if (!token) {
      throw new UnauthorizedException();
    }
    const { accessToken, refreshToken } =
      await this.authService.refreshToken(token);

    this.setRefreshTokenCookie(res, refreshToken);
    return { accessToken };
  }

  @Post('logout')
  @ApiOperation({ summary: 'Logout user' })
  @ApiResponse({ status: 200, description: 'Successfully logged out' })
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ message: string }> {
    const refreshToken = req.cookies?.refreshToken;

    if (refreshToken) {
      await this.authService.revokeRefreshToken(refreshToken);
    }

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: this.getIsProduction(),
      sameSite: this.getIsProduction() ? 'strict' : 'lax',
    });

    return { message: 'Logged out successfully' };
  }

  private setRefreshTokenCookie(res: Response, refreshToken: string): void {
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: this.getIsProduction(),
      sameSite: this.getIsProduction() ? 'strict' : 'lax',
      maxAge: this.configService.get<number>('jwt.refreshTokenMaxAge'),
      path: '/',
    });
  }

  private getIsProduction(): boolean {
    return this.configService.get<string>('app.nodeEnv') === 'production';
  }
}
