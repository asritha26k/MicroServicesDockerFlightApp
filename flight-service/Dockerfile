FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY target/*.jar flight-service.jar

EXPOSE 9002

ENTRYPOINT ["java", "-jar", "flight-service.jar"]
