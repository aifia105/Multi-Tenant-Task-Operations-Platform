import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import User from './schema/user.schema';
import { Repository } from 'typeorm';
import { UserResponseType } from './types/user-response.type';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async createUser(createUserDto: CreateUserDto): Promise<UserResponseType> {
    try {
      const user = await this.userRepository.create(createUserDto);
      await this.userRepository.save(user);
      return {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        role: user.role,
        status: user.status,
        createdAt: user.createdAt,
      };
    } catch (error) {
      throw new InternalServerErrorException('Failed to create user');
    }
  }

  async getUserByEmail(email: string): Promise<User> {
    try {
      const user = await this.userRepository.findOne({ where: { email } });
      if (!user) throw new NotFoundException(`User with not found`);
      return user;
    } catch (error) {
      throw new NotFoundException(`User with not found`);
    }
  }
}
