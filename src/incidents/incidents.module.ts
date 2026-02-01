import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { IncidentsService } from './incidents.service';
import { IncidentsController } from './incidents.controller';
import { Incident } from './incident.entity';
import { AuditLogModule } from '../audit-logs/audit-log.module';

@Module({
  imports: [TypeOrmModule.forFeature([Incident]), AuditLogModule],
  controllers: [IncidentsController],
  providers: [IncidentsService],
})
export class IncidentsModule {}
