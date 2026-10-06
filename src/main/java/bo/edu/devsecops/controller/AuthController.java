package bo.edu.devsecops.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    private final String adminUsername;
    private final String adminPassword;

    public AuthController(@Value("${app.auth.username}") String adminUsername,
                          @Value("${app.auth.password}") String adminPassword) {
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.getOrDefault("username", "");
        String password = credentials.getOrDefault("password", "");

        LOGGER.info("Intento de acceso: usuario={}", username);

        if (!adminPassword.isEmpty() && adminUsername.equals(username) && adminPassword.equals(password)) {
            return ResponseEntity.ok(Map.of(
                    "token", UUID.randomUUID().toString(),
                    "message", "Acceso autorizado"));
        }
        return ResponseEntity.status(401).body(Map.of("error", "Credenciales incorrectas"));
    }
}
