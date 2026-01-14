import { UserRoleType } from '../enum/user-role.enum';
import { UserStatusType } from '../enum/user-status.enum';

export type UserResponseType = {
  id: string;
  email: string;
  fullName: string;
  phoneNumber: string;
  role: UserRoleType;
  status: UserStatusType;
  organizationId: string;
  createdAt: Date;
};
