import { Body, Controller, Post, Req , UseGuards} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Incident } from './incident.entity';
import { User } from '../users/user.entity';
import { CreateIncidentDto } from './dto/create-incident.dto';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { log } from 'console';

@UseGuards(JwtAuthGuard)
@Controller('incidents')
export class IncidentsController {
  constructor(
    @InjectRepository(Incident)
    private readonly incidentRepo: Repository<Incident>,
  ) {}

  @Post()
  async createIncident(@Body() dto: CreateIncidentDto, @Req() req) {
    const user: User = req.user;
    console.log('USER:', req.user);


    const incident = this.incidentRepo.create({
      ...dto,
      createdBy: user, 
    });

    return await this.incidentRepo.save(incident);
    
  }
}
