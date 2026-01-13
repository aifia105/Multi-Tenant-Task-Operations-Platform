import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { UserStatus } from '../enum/user-status.enum';
import { UserRole } from '../enum/user-role.enum';

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

  @Column({ type: 'varchar', length: 255 })
  address: string;

  @Column({ type: 'varchar', length: 255 })
  phoneNumber: string;

  @Column({ type: 'varchar', length: 255, enum: UserRole })
  role: UserRole;

  @Column({ type: 'varchar', length: 255, enum: UserStatus })
  status: UserStatus;

  @Column({ type: 'varchar', length: 255 })
  createdAt: string;

  @Column({ type: 'varchar', length: 255 })
  updatedAt: string;
}

export default User;
