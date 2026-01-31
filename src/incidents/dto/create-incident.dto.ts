import { IsNotEmpty, IsEnum, IsOptional, IsString } from 'class-validator';
import { Severity } from '../enum/severity.enum';
import { ThreatType } from '../enum/threat-type.enum';
import { ApiProperty } from '@nestjs/swagger';

export class CreateIncidentDto {
  @IsNotEmpty()
  @IsString()
  @ApiProperty({ description: 'Malicious or suspicious URL' })
  maliciousURL: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty()
  httpResponse: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty()
  description: string;

  @IsEnum(Severity)
  @ApiProperty({ enum: Severity })
  severity: Severity;

  @IsEnum(ThreatType)
  @ApiProperty({ enum: ThreatType })
  threatType: ThreatType;

  @IsOptional()
  @IsString()
  @ApiProperty({ required: false })
  screenshot?: string;
}
