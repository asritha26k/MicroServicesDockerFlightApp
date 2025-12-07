FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY target/*.jar ticket-service.jar

EXPOSE 9003

ENTRYPOINT ["java", "-jar", "ticket-service.jar"]
