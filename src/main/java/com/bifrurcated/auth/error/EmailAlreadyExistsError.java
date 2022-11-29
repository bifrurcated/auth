package com.bifrurcated.auth.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class EmailAlreadyExistsError extends ResponseStatusException {
    public EmailAlreadyExistsError() {
        super(HttpStatus.BAD_REQUEST, "email already exists");
    }
}
