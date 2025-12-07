# Use a stable Temurin JDK
FROM eclipse-temurin:17-jdk

WORKDIR /app

# Copy the built Spring Boot jar into the image
# (Assumes you run `mvn clean package` so target/*.jar exists)
COPY target/*.jar config-server.jar

# Expose the config server port
EXPOSE 8888

# Optional: a lightweight healthcheck (works on modern Docker)
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD curl -f http://localhost:8888/actuator/health || exit 1

# Start the app
ENTRYPOINT ["java", "-jar", "config-server.jar"]
