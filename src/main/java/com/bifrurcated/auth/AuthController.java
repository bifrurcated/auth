package com.bifrurcated.auth;

import com.bifrurcated.auth.data.User;
import com.bifrurcated.auth.error.UnauthenticatedError;
import com.bifrurcated.auth.service.AuthService;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping(value = "/api")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    record RegisterRequest(
            @JsonProperty("first_name") String firstName,
            @JsonProperty("last_name") String lastName,
            String email,
            String password,
            @JsonProperty("password_confirm") String passwordConfirm
    ) {}
    record RegisterResponse(
            @JsonProperty("id") Long id,
            @JsonProperty("first_name") String firstName,
            @JsonProperty("last_name") String lastName,
            String email
    ) {}

    @PostMapping(value = "/register")
    public RegisterResponse register(@RequestBody RegisterRequest registerRequest) {
        var user = authService.register(
                registerRequest.firstName(),
                registerRequest.lastName(),
                registerRequest.email(),
                registerRequest.password(),
                registerRequest.passwordConfirm()
        );

        return new RegisterResponse(user.getId(), user.getFirstName(), user.getLastName(), user.getEmail());
    }

    record LoginRequest(
            String email,
            String password
    ) {}
    record LoginResponse(String token) {}

    @PostMapping(value = "/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        var login = authService.login(loginRequest.email(), loginRequest.password());

        Cookie cookie = new Cookie("refresh_token", login.getRefreshToken().getToken());
        cookie.setMaxAge(3600);
        cookie.setHttpOnly(true);
        cookie.setPath("/api");

        response.addCookie(cookie);

        return new LoginResponse(login.getAccessToken().getToken());
    }

    record UserResponse(
            @JsonProperty("id") Long id,
            @JsonProperty("first_name") String firstName,
            @JsonProperty("last_name") String lastName,
            String email
    ) {}

    @GetMapping(value = "/user")
    public UserResponse user(HttpServletRequest request) {
        var user = (User) request.getAttribute("user");

        return new UserResponse(user.getId(), user.getFirstName(), user.getLastName(), user.getEmail());
    }

    record RefreshResponse(String token) {}

    @PostMapping(value = "/refresh")
    public RefreshResponse refresh(@CookieValue("refresh_token") String refreshToken) {
        return new RefreshResponse(authService.refreshAccess(refreshToken).getAccessToken().getToken());
    }

    record LogoutResponse(String message) {}

    @PostMapping(value = "/logout")
    public LogoutResponse logout(@CookieValue("refresh_token") String refreshToken, HttpServletResponse response) {
        if (!authService.logout(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "cannot logout");
        }

        Cookie cookie = new Cookie("refresh_token", null);
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);

        response.addCookie(cookie);

        return new LogoutResponse("success");
    }

    record ForgotRequest(String email) {}
    record ForgotResponse(String message) {}

    @PostMapping(value = "/forgot")
    public ForgotResponse forgot(@RequestBody ForgotRequest forgotRequest, HttpServletRequest request) {
        var originUrl = request.getHeader(HttpHeaders.ORIGIN);

        authService.forgot(forgotRequest.email(), originUrl);

        return new ForgotResponse("success");
    }
}
