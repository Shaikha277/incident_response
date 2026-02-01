import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User , UserRole } from './user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async findById(id: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { id } });
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async findByUsername(username: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { username } });
  }
  async findAll(): Promise<User[]> {
    return this.userRepository.find({
      select: [
        'id',
        'email',
        'username',
        'firstName',
        'lastName',
        'role',
        'createdAt',
      ],
    });
  }

  async findOne(id: string): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id },
      select: [
        'id',
        'email',
        'username',
        'firstName',
        'lastName',
        'role',
        'createdAt',
        'updatedAt',
      ],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async updateRole(id: string, role: UserRole): Promise<User> {
    const user = await this.findOne(id);
    user.role = role;
    return this.userRepository.save(user);
  }

  async remove(id: string): Promise<void> {
    const user = await this.findOne(id);
    await this.userRepository.remove(user);
  }
}
