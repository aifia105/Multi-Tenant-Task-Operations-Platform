import { ApiProperty, PartialType } from '@nestjs/swagger';
import { RegisterDto } from 'src/auth/dto/register.dto';
import { UserStatus, type UserStatusType } from '../enum/user-status.enum';
import { IsDate, IsEnum, IsNotEmpty } from 'class-validator';

export class CreateUserDto extends PartialType(RegisterDto) {
  @ApiProperty({
    description: 'The status of the user',
    enum: UserStatus,
    default: UserStatus.ACTIVE,
  })
  @IsEnum(UserStatus)
  @IsNotEmpty()
  status: UserStatusType;

  @ApiProperty({
    description: 'The date the user was created',
    type: Date,
  })
  @IsDate()
  @IsNotEmpty()
  createdAt: Date;

  @ApiProperty({
    description: 'The date the user was last updated',
    type: Date,
  })
  @IsDate()
  @IsNotEmpty()
  updatedAt: Date;
}
