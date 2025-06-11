# Usa una imagen oficial de Java
FROM openjdk:21-jdk-slim

# Crea el directorio de trabajo en el contenedor
WORKDIR /app

# Copia el JAR compilado al contenedor
COPY target/auth-service-0.0.1-SNAPSHOT.jar app.jar

# Comando para ejecutar el JAR
ENTRYPOINT ["java", "-jar", "app.jar"]
