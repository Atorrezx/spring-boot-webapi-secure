# ---- Build stage ----
FROM maven:3.9-eclipse-temurin-21-alpine AS builder
WORKDIR /app

# Copy pom first (better layer caching)
COPY pom.xml .
RUN mvn -B dependency:go-offline

# Copy source and build
COPY src src
RUN mvn -B package -DskipTests

# ---- Runtime stage ----
FROM eclipse-temurin:21-jre-alpine

# Security: run as non-root user
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

WORKDIR /app

# Copy only the fat jar
COPY --from=builder /app/target/*.jar app.jar

EXPOSE 8080

# Health check (busybox wget, no curl in alpine)
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
