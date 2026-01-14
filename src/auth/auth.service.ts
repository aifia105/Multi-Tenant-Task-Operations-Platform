import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { UserResponseType } from 'src/users/types/user-response.type';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from './types/jwt-payload.type';
import { LoginDto } from './dto/login.dto';
import { UserStatus } from 'src/users/enum/user-status.enum';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { RefreshToken } from './schema/refresh-token.schema';
import { Model } from 'mongoose';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    @InjectModel(RefreshToken.name)
    private readonly refreshTokenModel: Model<RefreshToken>,
  ) {}

  async validateUser(
    email: string,
    password: string,
  ): Promise<UserResponseType | null> {
    const user = await this.usersService.getUserByEmail(email);
    if (!user) return null;

    const match = await bcrypt.compare(password, user.password);
    if (!match) return null;

    return {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      phoneNumber: user.phoneNumber,
      role: user.role,
      status: user.status,
      createdAt: user.createdAt,
    };
  }

  async register(registerDto: RegisterDto): Promise<{
    message: string;
  }> {
    try {
      const existingUser = await this.usersService.getUserByEmail(
        registerDto.email,
      );
      if (existingUser) {
        throw new ConflictException('Email already exists');
      }
      const saltRounds = this.configService.get<number>('saltRounds');
      const hashedPassword = await bcrypt.hash(
        registerDto.password,
        saltRounds,
      );

      const user = await this.usersService.createUser({
        ...registerDto,
        password: hashedPassword,
        status: UserStatus.ACTIVE,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      if (!user) {
        throw new InternalServerErrorException('Failed to create user');
      }

      return {
        message: 'User registered successfully',
      };
    } catch (error) {
      throw new InternalServerErrorException('Failed to register user');
    }
  }

  async login(loginDto: LoginDto): Promise<{
    user: UserResponseType;
    accessToken: string;
    refreshToken: string;
  }> {
    try {
      const user = await this.usersService.getUserByEmail(loginDto.email);
      if (!user) {
        throw new UnauthorizedException('Invalid credentials');
      }

      const match = await bcrypt.compare(loginDto.password, user.password);
      if (!match) {
        throw new UnauthorizedException('Invalid credentials');
      }

      if (user.status === UserStatus.INACTIVE) {
        throw new UnauthorizedException('Invalid account');
      }

      const { accessToken, refreshToken } = await this.generateTokens(user);

      const salt = this.configService.get<number>('saltRounds');

      const hashedRefreshToken = await bcrypt.hash(refreshToken, salt);

      await this.refreshTokenModel.create({
        userId: user.id,
        token: hashedRefreshToken,
        expiresAt: this.configService.get<string>('jwt.refreshTokenExpiresIn'),
      });

      return {
        user: {
          id: user.id,
          email: user.email,
          fullName: user.fullName,
          phoneNumber: user.phoneNumber,
          role: user.role,
          status: user.status,
          createdAt: user.createdAt,
        },
        accessToken,
        refreshToken,
      };
    } catch (error) {
      throw new InternalServerErrorException('Failed to login');
    }
  }

  async generateTokens(user: UserResponseType): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    try {
      const payload: JwtPayload = {
        sub: user.id,
        email: user.email,
        role: user.role,
      };

      const accessTokenExporesIn =
        this.configService.get<string>('jwt.expiresIn');
      const refreshTokenExporesIn = this.configService.get<string>(
        'jwt.refreshTokenExpiresIn',
      );

      if (!accessTokenExporesIn || !refreshTokenExporesIn) {
        throw new InternalServerErrorException('JWT configuration is missing');
      }

      const accessToken = this.jwtService.sign(payload, {
        secret: this.configService.get<string>('jwt.accessSecret'),
        expiresIn: parseInt(accessTokenExporesIn),
      });

      const refreshToken = this.jwtService.sign(payload, {
        secret: this.configService.get<string>('jwt.refreshSecret'),
        expiresIn: parseInt(refreshTokenExporesIn),
      });

      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      throw new InternalServerErrorException('Failed to generate tokens');
    }
  }
}
