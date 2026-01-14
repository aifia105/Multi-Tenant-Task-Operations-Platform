import { ApiProperty, PartialType } from '@nestjs/swagger';
import { RegisterDto } from 'src/auth/dto/register.dto';
import { UserStatus, type UserStatusType } from '../enum/user-status.enum';
import {
  IsDate,
  IsEnum,
  IsNotEmpty,
  IsUUID,
  ValidateIf,
} from 'class-validator';

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
    description: 'The ID of the organization the user belongs to',
    type: 'string',
    format: 'uuid',
    required: false,
  })
  @ValidateIf((o) => o.role !== 'ADMIN')
  @IsNotEmpty({ message: 'Organization ID is required for non-admin users' })
  @IsUUID()
  organizationId?: string;

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
