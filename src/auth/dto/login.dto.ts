import { IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsNotEmpty()
  identifier: string; // email|username

  @IsString()
  @IsNotEmpty()
  password: string;
}
