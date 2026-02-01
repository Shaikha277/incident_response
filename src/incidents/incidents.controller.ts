import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Req,
  UseGuards,
} from '@nestjs/common';
import { IncidentsService } from './incidents.service';
import { CreateIncidentDto } from './dto/create-incident.dto';
import { UpdateIncidentDto } from './dto/update-incident.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import type { Request } from 'express';

@Controller('incidents')
@UseGuards(JwtAuthGuard)
export class IncidentsController {
  constructor(private readonly incidentsService: IncidentsService) {}

  @Post()
  create(@Body() createIncidentDto: CreateIncidentDto, @Req() req: any) {
    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];
    return this.incidentsService.create(
      createIncidentDto,
      req.user,
      ipAddress,
      userAgent,
    );
  }

  @Get()
  findAll(@Req() req: any) {
    return this.incidentsService.findAll(req.user);
  }

  @Get(':id')
  findOne(@Param('id') id: string, @Req() req: any) {
    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];
    return this.incidentsService.findOne(id, req.user, ipAddress, userAgent);
  }

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateIncidentDto: UpdateIncidentDto,
    @Req() req: any,
  ) {
    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];
    return this.incidentsService.update(
      id,
      updateIncidentDto,
      req.user,
      ipAddress,
      userAgent,
    );
  }

  @Delete(':id')
  remove(@Param('id') id: string, @Req() req: any) {
    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];
    return this.incidentsService.remove(id, req.user, ipAddress, userAgent);
  }
}
