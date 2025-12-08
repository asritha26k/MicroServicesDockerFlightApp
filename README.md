# MicroServices Flight Application

A comprehensive microservices-based flight booking application built with Spring Boot, Spring Cloud, and Docker. This project demonstrates a distributed system architecture with multiple services communicating through a service registry.

##  Project Overview

This is a modular microservices application that handles flight bookings, passenger management, tickets, authentication, and email notifications. The system uses Docker containerization for easy deployment and scalability.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    API Gateway (8765)                       │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐   ┌──────────────┐
│Flight Service│    │Passenger Srv │   │ Ticket Srv   │
│   (8081)     │    │   (8082)     │   │   (8083)     │
└──────────────┘    └──────────────┘   └──────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
        ┌───────▼─────────┐    ┌───────▼────────┐
        │  Auth Service   │    │ Email Service  │
        │   (8085)        │    │   (8087)       │
        └─────────────────┘    └────────────────┘
```

##  Services

### 1. **Service Registry (Eureka)**
- **Port:** 8761
- **Purpose:** Service discovery and registration using Spring Cloud Eureka
- **Location:** `service-registry/`

### 2. **API Gateway**
- **Port:** 8765
- **Purpose:** Single entry point for all client requests, routes requests to appropriate services
- **Location:** `api-gateway/`

### 3. **Config Server**
- **Port:** 8888
- **Purpose:** Centralized configuration management for all services
- **Location:** `ConfigServer/`

### 4. **Flight Service**
- **Port:** 8081
- **Purpose:** Manages flight information, schedules, and availability
- **Database:** PostgreSQL
- **Location:** `flight-service/`

### 5. **Passenger Service**
- **Port:** 8082
- **Purpose:** Manages passenger information and profiles
- **Database:** PostgreSQL
- **Location:** `passenger-service/`

### 6. **Ticket Service**
- **Port:** 8083
- **Purpose:** Handles ticket booking and management
- **Database:** PostgreSQL
- **Location:** `ticket-service/`

### 7. **Auth Service**
- **Port:** 8085
- **Purpose:** User authentication and authorization using Spring Security
- **Database:** MySQL
- **Location:** `auth-service/`

### 8. **Email Service**
- **Port:** 8087
- **Purpose:** Handles email notifications for bookings and confirmations
- **Location:** `email-service/`

##  Getting Started

### Prerequisites

- **Docker** and **Docker Compose**
- **Java 11+** (for local development without Docker)
- **Maven 3.6+**

### Quick Start with Docker

1. **Navigate to the project root:**
   ```powershell
   cd Week8Assignment
   ```

2. **Build and start all services:**
   ```powershell
   docker-compose up --build
   ```

   This will start all services with their respective databases and networking configured.

3. **Verify services are running:**
   ```powershell
   docker ps
   ```

4. **Access services:**
   - **API Gateway:** http://localhost:8765
   - **Eureka Server:** http://localhost:8761
   - **Config Server:** http://localhost:8888

### Local Development (Without Docker)

1. **Build the entire project:**
   ```powershell
   mvn clean install
   ```

2. **Start services in order:**
   - Start Eureka Server (service-registry)
   - Start Config Server (ConfigServer)
   - Start Auth Service (auth-service)
   - Start remaining services (flight, passenger, ticket, email)
   - Start API Gateway (api-gateway)

##  Project Structure

```
Week8Assignment/
├── api-gateway/              # Spring Cloud Gateway
├── auth-service/             # Spring Security Authentication
│   └── mysql-init/           # Database initialization scripts
├── ConfigServer/             # Spring Cloud Config Server
├── email-service/            # Email notification service
├── flight-service/           # Flight management service
├── passenger-service/        # Passenger management service
├── ticket-service/           # Ticket booking service
├── service-registry/         # Eureka Service Registry
├── docker-compose.yml        # Docker Compose configuration
├── pom.xml                   # Parent Maven POM
└── README.md                 # This file
```

##  Technology Stack

- **Framework:** Spring Boot 2.x / 3.x
- **Cloud Services:** Spring Cloud (Eureka, Gateway, Config)
- **Security:** Spring Security
- **Databases:** PostgreSQL (microservices), MySQL (auth-service)
- **Build Tool:** Apache Maven
- **Containerization:** Docker & Docker Compose
- **Service Communication:** REST APIs

##  API Endpoints

### Through API Gateway (localhost:8765)

Each service's endpoints are accessible through the gateway with the following pattern:
```
http://localhost:8765/<service-name>/<endpoint>
```

Example routes:
- Flight Service: `/flight-service/flights`
- Passenger Service: `/passenger-service/passengers`
- Ticket Service: `/ticket-service/tickets`
- Auth Service: `/auth-service/auth`

##  Database Configuration

### PostgreSQL Services
- **Host:** postgres-db
- **Port:** 5433 (mapped from 5432)
- **Services:** flight-service, passenger-service, ticket-service

### MySQL (Auth Service)
- **Host:** mysql-db
- **Port:** 3306
- **Database:** Initialized from `auth-service/mysql-init/init.sql`
- **Root Password:** yourpassword (update in production)

##  Security

- **Authentication:** Handled by Auth Service using Spring Security
- **API Gateway:** Provides a single entry point with request routing and filtering
- **Eureka:** Service-to-service communication within internal network

##  Docker Compose Services

The `docker-compose.yml` orchestrates:
- Network isolation (`app-net` bridge network)
- Health checks for all services
- Service dependencies and startup order
- Volume mounting for database initialization
- Environment variable configuration

##  Troubleshooting

### Services not starting
1. Check if ports are already in use
2. Review Docker logs: `docker logs <container-name>`
3. Verify network connectivity: `docker network ls`

### Database connection issues
- Ensure database containers are healthy
- Check credentials in docker-compose.yml
- Verify volume mounts for init scripts

### Service discovery issues
- Check Eureka dashboard at http://localhost:8761
- Verify services are registered
- Check Config Server connectivity

## 📊 Monitoring

- **Eureka Dashboard:** http://localhost:8761 - View all registered services
- **Config Server:** http://localhost:8888 - Access centralized configuration
- **Docker Logs:** `docker-compose logs -f` - Stream logs from all services

##  Stopping the Application

```powershell
docker-compose down
```

To also remove volumes:
```powershell
docker-compose down -v
```


