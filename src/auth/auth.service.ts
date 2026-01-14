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
      organizationId: user.organizationId,
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
      const saltRounds = this.configService.get<number>('app.saltRounds');
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

      const hashedRefreshToken = await this.hashToken(refreshToken);

      await this.refreshTokenModel.create({
        userId: user.id,
        tokenHash: hashedRefreshToken,
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
          organizationId: user.organizationId,
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
        orgId: user.organizationId,
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

  async refreshToken(token: string): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    try {
      const payload = await this.verifyRefreshToken(token);

      const user = await this.usersService.getUserByEmail(payload.email);
      if (!user || user.status !== UserStatus.ACTIVE) {
        throw new UnauthorizedException('Invalid or inactive token');
      }

      const hashedRefreshToken = await this.hashToken(token);

      const existingToken = await this.refreshTokenModel.findOne({
        tokenHash: hashedRefreshToken,
        userId: payload.sub,
      });
      if (!existingToken) {
        throw new UnauthorizedException('Invalid token');
      }

      await this.refreshTokenModel.deleteOne({ _id: existingToken._id });

      const { accessToken, refreshToken } = await this.generateTokens(user);

      await this.storeRefreshToken(user.id, refreshToken);

      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  async getCurrentUser(token: string): Promise<UserResponseType> {
    try {
      const decoded = this.jwtService.verify<JwtPayload>(token, {
        secret: this.configService.get<string>('jwt.accessSecret'),
      });

      if (!decoded) {
        throw new UnauthorizedException('Invalid token');
      }

      const user = await this.usersService.getUserByEmail(decoded.email);

      if (!user) {
        throw new UnauthorizedException('Invalid token');
      }

      return {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        role: user.role,
        status: user.status,
        organizationId: user.organizationId,
        createdAt: user.createdAt,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  async revokeRefreshToken(token: string): Promise<void> {
    try {
      const hashedRefreshToken = await this.hashToken(token);

      await this.refreshTokenModel.deleteOne({ tokenHash: hashedRefreshToken });
    } catch (error) {
      throw new InternalServerErrorException('Failed to revoke refresh token');
    }
  }

  private async hashToken(token: string): Promise<string> {
    const saltRounds = this.configService.get<number>('app.saltRounds');
    return bcrypt.hash(token, saltRounds);
  }

  private async verifyRefreshToken(token: string): Promise<JwtPayload> {
    try {
      return await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>('jwt.refreshSecret'),
      });
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  private async storeRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const hashedToken = await this.hashToken(refreshToken);
    const expiresIn = this.configService.get<string>(
      'jwt.refreshTokenExpiresIn',
    );

    if (!expiresIn) {
      throw new InternalServerErrorException('JWT configuration is missing');
    }

    const expiresAt = new Date();
    expiresAt.setSeconds(
      expiresAt.getSeconds() + this.parseExpiration(expiresIn),
    );

    await this.refreshTokenModel.create({
      userId,
      tokenHash: hashedToken,
      expiresAt,
    });
  }

  private parseExpiration(expiresIn: string): number {
    const match = expiresIn.match(/^(\d+)([smhd])$/);
    if (!match) return 7 * 24 * 60 * 60;
    const [, value, unit] = match;
    const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
    return parseInt(value) * multipliers[unit];
  }
}
