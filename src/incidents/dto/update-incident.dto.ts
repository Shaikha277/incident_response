import { IsOptional, IsEnum, IsString } from 'class-validator';
import { Severity } from '../enum/severity.enum';
import { ThreatType } from '../enum/threat-type.enum';
import { IncidentStatus } from '../enum/incident-status.enum';

export class UpdateIncidentDto {
  @IsOptional()
  @IsString()
  maliciousURL?: string;

  @IsOptional()
  @IsString()
  httpResponse?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

  @IsOptional()
  @IsEnum(ThreatType)
  threatType?: ThreatType;

  @IsOptional()
  @IsEnum(IncidentStatus)
  status?: IncidentStatus;

  @IsOptional()
  @IsString()
  screenshot?: string;
}
