import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { getRepositoryToken } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { User } from './users/user.entity';
import { UserRole } from './users/user.entity';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
  const config = new DocumentBuilder()
    .setTitle('Incident Response API')
    .setDescription('Cybersecurity Incident Reporting Backend')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  
  await seedAdmin(app);

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  await app.listen(process.env.PORT ?? 3000);
}
async function seedAdmin(app) {
  const userRepo = app.get(getRepositoryToken(User));

  const adminEmail = 'admin@company.com';

  const existingAdmin = await userRepo.findOne({
    where: { email: adminEmail },
  });

  if (!existingAdmin) {
    const admin = userRepo.create({
      email: adminEmail,
      username: "admin",
      firstName:"Admin",
      lastName:"User",
      password: await bcrypt.hash('Admin@123!!', 10),
      role: UserRole.ADMIN,
    });

    await userRepo.save(admin);
    console.log('Admin user created');
  }
}

bootstrap();
