import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import type { UserStatus, UserStatusType } from '../enum/user-status.enum';
import type { UserRole, UserRoleType } from '../enum/user-role.enum';

@Entity()
class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255, unique: true })
  email: string;

  @Column({ type: 'varchar', length: 255 })
  password: string;

  @Column({ type: 'varchar', length: 255 })
  fullName: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  address: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  phoneNumber: string;

  @Column({ type: 'varchar', length: 255 })
  role: UserRoleType;

  @Column({ type: 'varchar', length: 255 })
  status: UserStatusType;

  @Column({ type: 'uuid', nullable: false })
  organizationId: string;

  @Column({ type: 'timestamp' })
  createdAt: Date;

  @Column({ type: 'timestamp' })
  updatedAt: Date;
}

export default User;
