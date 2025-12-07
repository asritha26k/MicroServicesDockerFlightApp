FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY target/*.jar service-registry.jar

EXPOSE 8761

ENTRYPOINT ["java", "-jar", "service-registry.jar"]
