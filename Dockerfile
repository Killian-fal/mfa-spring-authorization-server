# Stage 1: Build the application
FROM openjdk:21-jdk-buster AS build

COPY . /home/gradle/
WORKDIR /home/gradle

RUN ./gradlew build

# Stage 2: Run the application
FROM build AS runner

VOLUME /tmp

EXPOSE 9000

ARG JAR_FILE=/home/gradle/build/libs/mfa-spring-authorization-server-0.0.1-SNAPSHOT.jar
COPY --from=build ${JAR_FILE} /app.jar

ENTRYPOINT ["java","-jar","/app.jar"]