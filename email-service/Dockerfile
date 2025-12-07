# Use a minimal JDK image
FROM eclipse-temurin:17-jdk-alpine

# Set working directory
WORKDIR /app

# Copy jar to container
COPY target/*.jar email-service.jar

# Expose service port
EXPOSE 9005

# Environment variables (OPTIONAL but recommended for container environments)
ENV SPRING_APPLICATION_NAME=email-service \
    SERVER_PORT=9005 \
    SPRING_KAFKA_BOOTSTRAP_SERVERS=host.docker.internal:9092 \
    SPRING_KAFKA_CONSUMER_GROUP_ID=email-group

# Run the service
ENTRYPOINT ["java", "-jar", "email-service.jar"]
