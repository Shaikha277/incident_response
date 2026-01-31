import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  CreateDateColumn,
  JoinColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../users/user.entity';
import { IncidentStatus } from './enum/incident-status.enum';
import { ThreatType } from './enum/threat-type.enum';
import { Severity } from './enum/severity.enum';

@Entity()
export class Incident {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('text')
  maliciousURL: string;

  @Column('text')
  httpResponse: string;

  @Column('text')
  description: string;

  @Column({
    type: 'enum',
    enum: Severity,
  })
  severity: Severity;

  @Column({
    type: 'enum',
    enum: ThreatType,
  })
  threatType: ThreatType;

  @Column({
    type: 'enum',
    enum: IncidentStatus,
    default: IncidentStatus.PENDING,
  })
  status: IncidentStatus;

  @Column({ nullable: true })
  screenshot: string;

  @CreateDateColumn({ type: 'timestamp', precision: 0 })
  timestamp: Date;

  @Column({ name: 'created_by_id' })
  createdById: string;

  @ManyToOne(() => User, (user) => user.incidents, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'created_by_id' })
  createdBy: User;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
