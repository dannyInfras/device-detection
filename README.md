# Enterprise-Grade Device Detection and Email Verification

This NestJS application provides enterprise-grade device detection and email verification capabilities. It follows domain-driven design principles and clean architecture patterns.

## Features

- Device detection and fingerprinting
- Email verification for new devices
- JWT-based authentication
- Role-based authorization
- Circuit breaker pattern for external services
- Event-driven architecture with Kafka
- Caching with Redis
- Data encryption for sensitive information

## Architecture

The application is structured following domain-driven design (DDD) principles:

- **Domain Layer**: Contains the core business logic, entities, and repository interfaces
- **Application Layer**: Orchestrates the domain logic through use cases
- **Infrastructure Layer**: Provides implementations for interfaces (repositories, services)
- **Presentation Layer**: Handles HTTP requests through controllers

## Project Structure

\`\`\`
src/
├── common/                 # Shared utilities, interfaces, and services
│   ├── decorators/         # Custom decorators
│   ├── guards/             # Authentication and authorization guards
│   ├── interceptors/       # Request/response interceptors
│   ├── interfaces/         # Common interfaces
│   ├── services/           # Shared services
│   └── utils/              # Utility functions and classes
├── config/                 # Application configuration
├── modules/                # Feature modules
│   ├── device/             # Device detection module
│   │   ├── domain/         # Domain entities, repositories, events
│   │   ├── application/    # Use cases, DTOs
│   │   ├── infrastructure/ # Repository implementations, services
│   │   └── device.module.ts
│   └── auth/               # Authentication module
│       ├── domain/         # Domain entities, repositories, events
│       ├── application/    # Use cases, DTOs
│       ├── infrastructure/ # Repository implementations, services
│       ├── presentation/   # Controllers
│       └── auth.module.ts
├── app.module.ts           # Main application module
└── main.ts                 # Application entry point
\`\`\`

## Getting Started

### Prerequisites

- Node.js (v16+)
- PostgreSQL
- Redis
- Kafka

### Installation

1. Clone the repository
2. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`
3. Configure environment variables:
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your configuration
   \`\`\`
4. Start the application:
   \`\`\`bash
   npm run start:dev
   \`\`\`

### API Documentation

The API documentation is available at `/api` when the application is running. It is generated using Swagger.

## Testing

\`\`\`bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov
