FROM eclipse-temurin:21-jdk-jammy
WORKDIR /app
COPY target/authServiceInno-1.0-SNAPSHOT.jar app.jar
ENV SPRING_PROFILES_ACTIVE=docker
ENTRYPOINT ["java", "-jar", "app.jar"]