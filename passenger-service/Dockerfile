FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY target/*.jar passenger-service.jar

EXPOSE 9001

ENTRYPOINT ["java", "-jar", "passenger-service.jar"]
