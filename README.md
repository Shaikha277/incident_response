# Incident Response Backend API

A secure backend system for reporting, managing, and auditing cybersecurity incidents.
Built with **NestJS**, **TypeORM**, and **PostgreSQL**, focusing on role-based access control,
audit logging, and incident lifecycle management.

---

## 🚀 Features

### 🔐 Authentication & Authorization
- User registration and login (JWT-based authentication)
- Role-based access control (ADMIN / USER)
- Account lockout after multiple failed login attempts
- Secure password hashing with bcrypt

### 👤 User Management
- Admin-only user listing and role updates
- UUID-based user identification
- Support for multiple authentication providers (Local, Google – planned)

### 🚨 Incident Management
- Create, view, update, and delete incidents
- Incident ownership enforcement
- Admins can view and manage all incidents
- Incident status lifecycle:
  - Pending
  - In Progress
  - Resolved
  - Closed

### 🧾 Audit Logging
- Full audit trail for security-sensitive actions:
  - User registration & login
  - Failed login attempts
  - Account lock events
  - Incident CRUD operations
  - Unauthorized access attempts
- IP address and user-agent tracking
- Indexed audit logs for performance

### 📄 API Documentation
- Auto-generated Swagger documentation
- JWT Bearer authentication support

---

## 🛠 Tech Stack

- **Framework:** NestJS  
- **Language:** TypeScript  
- **Database:** PostgreSQL  
- **ORM:** TypeORM  
- **Auth:** JWT + Passport  
- **Validation:** class-validator  
- **Docs:** Swagger (OpenAPI)

---



---

## ⚙️ Environment Variables

Create a `.env` file:

```env
NODE_ENV=development
PORT=3000

DB_HOST=localhost
DB_PORT=5434
DB_USER=postgres
DB_PASS=password
DB_NAME=incident_response

JWT_SECRET=941b4526e307291c20fa231fd09bbef69ded50a7a5ca522972a347ae213478c7
JWT_REFRESH_SECRET=3f82f4335135b6d7e2930b5dde28ee96195736038f8861ca0128ae10456b09ed
JWT_EXPIRES_IN=20m
JWT_REFRESH_EXPIRES_IN=7d

SALT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCK_TIME=900000

```
## Running the Project 
```
npm install
npm run start:dev
```
---
## Swagger UI will be available at:
```
http://localhost:3000/api
```

## An admin account is automatically seeded on startup:
- Email: admin@company.com
- Password: Admin@123!!



