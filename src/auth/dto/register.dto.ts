import { UserRole, type UserRoleType } from 'src/users/enum/user-role.enum';
import {
  IsString,
  IsNotEmpty,
  IsEmail,
  MinLength,
  IsOptional,
  IsPhoneNumber,
  IsEnum,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterDto {
  @ApiProperty({
    example: 'Xin Zhao',
    description: 'The full name of the User',
    format: 'string',
    type: 'string',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;
  @ApiProperty({
    example: 'password12345678',
    description: 'The password of the User',
    format: 'string',
    type: 'string',
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(16)
  password: string;
  @ApiProperty({
    example: 'Xin Zhao',
    description: 'The full name of the User',
    format: 'string',
    type: 'string',
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  fullName: string;
  @ApiProperty({
    example: '123 Main St',
    description: 'The address of the User',
    format: 'string',
    type: 'string',
  })
  @IsString()
  @IsOptional()
  address: string;
  @ApiProperty({
    example: '+8613800138000',
    description: 'The phone number of the User',
    format: 'string',
    type: 'string',
  })
  @IsPhoneNumber()
  @IsOptional()
  phoneNumber: string;
  @ApiProperty({
    example: 'ORGANIZATIONMANAGER',
    description: 'The role of the User',
    format: 'string',
    type: 'string',
  })
  @IsEnum(UserRole)
  @IsNotEmpty()
  role: UserRoleType;
}
