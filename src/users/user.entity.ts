import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { Incident } from '../incidents/incident.entity';
import { Exclude } from 'class-transformer';
import { AuditLog } from 'src/audit-logs/audit-log.entity';

export enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
}
export enum AuthProvider {
  LOCAL = 'LOCAL',
  GOOGLE = 'GOOGLE',
}

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  @Index()
  email: string;

  @Column({ unique: true })
  username: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column({ nullable: true })
  @Exclude()
  password: string;

  @Column({
    type: 'enum',
    enum: AuthProvider,
    default: AuthProvider.LOCAL,
  })
  provider: AuthProvider;

  @Column({ name: 'google_id', nullable: true, unique: true })
  googleId: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.USER,
  })
  role: UserRole;

  @Column({ name: 'is_locked', default: false })
  isLocked: boolean;

  @Column({ name: 'login_attempts', default: 0 })
  loginAttempts: number;

  @Column({ name: 'locked_until', type: 'timestamp', nullable: true })
  lockedUntil: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @OneToMany(() => Incident, (incident) => incident.createdBy)
  incidents: Incident[];

  @OneToMany(() => AuditLog, (auditLog) => auditLog.user)
  auditLogs: AuditLog[];

  isAccountLocked(): boolean {
    if (!this.isLocked) return false;
    if (!this.lockedUntil) return this.isLocked;

    const now = new Date();
    if (now > this.lockedUntil) {
      return false;
    }
    return true;
  }

  get fullName(): string {
    return `${this.firstName} ${this.lastName}`;
  }
}
