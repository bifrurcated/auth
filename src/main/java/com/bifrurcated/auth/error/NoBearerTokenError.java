package com.bifrurcated.auth.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class NoBearerTokenError extends ResponseStatusException {
    public NoBearerTokenError() {
        super(HttpStatus.BAD_REQUEST, "no bearer refreshToken");
    }
}
