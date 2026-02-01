import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Incident } from './incident.entity';
import { CreateIncidentDto } from './dto/create-incident.dto';
import { UpdateIncidentDto } from './dto/update-incident.dto';
import { User, UserRole } from '../users/user.entity';
import { AuditLogsService } from '../audit-logs/audit-log.service';
import { AuditAction } from '../audit-logs/enum/audit-action.enum';

@Injectable()
export class IncidentsService {
  constructor(
    @InjectRepository(Incident)
    private incidentRepository: Repository<Incident>,
    private auditLogsService: AuditLogsService,
  ) {}

  async create(
    createIncidentDto: CreateIncidentDto,
    user: User,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<Incident> {
    const incident = this.incidentRepository.create({
      ...createIncidentDto,
      createdBy: user,
    });

    const savedIncident = await this.incidentRepository.save(incident);

    await this.auditLogsService.log({
      userId: user.id,
      action: AuditAction.INCIDENT_CREATED,
      resourceType: 'incident',
      resourceId: savedIncident.id,
      status: 'success',
      ipAddress,
      userAgent,
      details: `Created incident with severity: ${savedIncident.severity}`,
    });

    return savedIncident;
  }

  async findAll(user: User): Promise<Incident[]> {
    if (user.role === UserRole.ADMIN) {
      return this.incidentRepository.find({
        relations: ['createdBy'],
        order: { timestamp: 'DESC' },
      });
    }

    return this.incidentRepository.find({
      where: { createdById: user.id },
      relations: ['createdBy'],
      order: { timestamp: 'DESC' },
    });
  }

  async findOne(
    id: string,
    user: User,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<Incident> {
    const incident = await this.incidentRepository.findOne({
      where: { id },
      relations: ['createdBy'],
    });

    if (!incident) {
      throw new NotFoundException('Incident not found');
    }

    if (user.role !== UserRole.ADMIN && incident.createdById !== user.id) {
      await this.auditLogsService.log({
        userId: user.id,
        action: AuditAction.UNAUTHORIZED_ACCESS,
        resourceType: 'incident',
        resourceId: id,
        status: 'failed',
        ipAddress,
        userAgent,
        details: 'User attempted to view an incident without permission',
      });

      throw new ForbiddenException('Access denied');
    }

    await this.auditLogsService.log({
      userId: user.id,
      action: AuditAction.INCIDENT_VIEWED,
      resourceType: 'incident',
      resourceId: incident.id,
      status: 'success',
      ipAddress,
      userAgent,
    });

    return incident;
  }

  async update(
    id: string,
    updateIncidentDto: UpdateIncidentDto,
    user: User,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<Incident> {
    const incident = await this.incidentRepository.findOne({
      where: { id },
    });

    if (!incident) {
      throw new NotFoundException('Incident not found');
    }

    if (user.role !== UserRole.ADMIN && incident.createdById !== user.id) {
      await this.auditLogsService.log({
        userId: user.id,
        action: AuditAction.UNAUTHORIZED_ACCESS,
        resourceType: 'incident',
        resourceId: id,
        status: 'failed',
        ipAddress,
        userAgent,
        details: 'User attempted to update an incident without permission',
      });
      throw new ForbiddenException('Access denied');
    }

    Object.assign(incident, updateIncidentDto);
    const updatedIncident = await this.incidentRepository.save(incident);

    await this.auditLogsService.log({
      userId: user.id,
      action: AuditAction.INCIDENT_UPDATED,
      resourceType: 'incident',
      resourceId: incident.id,
      status: 'success',
      ipAddress,
      userAgent,
      details: `Updated incident fields: ${Object.keys(updateIncidentDto).join(', ')}`,
    });

    return updatedIncident;
  }

  async remove(
    id: string,
    user: User,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    const incident = await this.incidentRepository.findOne({
      where: { id },
    });

    if (!incident) {
      throw new NotFoundException('Incident not found');
    }

    if (user.role !== UserRole.ADMIN && incident.createdById !== user.id) {
      await this.auditLogsService.log({
        userId: user.id,
        action: AuditAction.UNAUTHORIZED_ACCESS,
        resourceType: 'incident',
        resourceId: id,
        status: 'failed',
        ipAddress,
        userAgent,
        details: 'User attempted to delete an incident without permission',
      });

      throw new ForbiddenException('Access denied');
    }

    await this.incidentRepository.remove(incident);

    await this.auditLogsService.log({
      userId: user.id,
      action: AuditAction.INCIDENT_DELETED,
      resourceType: 'incident',
      resourceId: id,
      status: 'success',
      ipAddress,
      userAgent,
      details: `Deleted incident with severity: ${incident.severity}`,
    });
  }
}
