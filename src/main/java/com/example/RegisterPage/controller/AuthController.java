package com.example.RegisterPage.controller;

import com.example.RegisterPage.entity.User;
import com.example.RegisterPage.service.AuthService;
import com.example.RegisterPage.service.JwtService;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class AuthController {

    private static final String JWT_COOKIE = "JWT";
    private static final int COOKIE_MAX_AGE_SECONDS = 60 * 60;

    private final AuthService authService;
    private final JwtService jwtService;

    public AuthController(AuthService authService,JwtService jwtService) {

        this.authService = authService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public String register(@RequestBody User user) {

        return authService.register(user);
    }

    @PostMapping("/login")
    public String login(@RequestBody User user,
                        HttpServletResponse response) {

        String result = authService.login(user);

        if (result.equals("Login successful")) {

            String token = jwtService.generateToken(user.getEmail());

            ResponseCookie cookie =
                    ResponseCookie.from(JWT_COOKIE, token)
                            .httpOnly(true)
                            .secure(false) // true in HTTPS production
                            .path("/")
                            .maxAge(COOKIE_MAX_AGE_SECONDS)
                            .sameSite("Lax")
                            .build();

            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        }

        return result;
    }
}