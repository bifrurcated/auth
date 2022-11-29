package com.bifrurcated.auth.service;

import com.bifrurcated.auth.data.PasswordRecovery;
import com.bifrurcated.auth.data.Token;
import com.bifrurcated.auth.data.User;
import com.bifrurcated.auth.data.UserRepo;
import com.bifrurcated.auth.error.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.relational.core.conversion.DbActionExecutionException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final String accessTokenSecret;
    private final String refreshTokenSecret;
    private final MailService mailService;
    private final Long accessTokenValidity;
    private final Long refreshTokenValidity;

    @Autowired
    public AuthService(
            UserRepo userRepo,
            PasswordEncoder passwordEncoder,
            @Value("${application.security.access-token-secret}") String accessTokenSecret,
            @Value("${application.security.refresh-token-secret}") String refreshTokenSecret,
            MailService mailService,
            @Value("${application.security.access-token-validity}") Long accessTokenValidity,
            @Value("${application.security.refresh-token-validity}") Long refreshTokenValidity) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenSecret = accessTokenSecret;
        this.refreshTokenSecret = refreshTokenSecret;
        this.mailService = mailService;
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    public User register(String firstName, String lastName, String email, String password, String passwordConfirm) {
        if (!Objects.equals(password, passwordConfirm)) {
            throw new PasswordDoNotMatchError();
        }
        User user;
        try {
            user = userRepo.save(User.of(firstName, lastName, email, passwordEncoder.encode(password)));
        } catch (DbActionExecutionException exception) {
            throw new EmailAlreadyExistsError();
        }
        return user;
    }

    public Login login(String email, String password) {
        var user = userRepo.findByEmail(email)
                .orElseThrow(InvalidCredentialsError::new);

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new InvalidCredentialsError();
        }
        var login = Login.of(user.getId(), accessTokenSecret, accessTokenValidity, refreshTokenSecret, refreshTokenValidity);
        var refreshJwt = login.getRefreshToken();

        user.addToken(new Token(refreshJwt.getToken(), refreshJwt.getIssueAt(), refreshJwt.getExpiration()));
        userRepo.save(user);

        return login;
    }

    public User getUserFromToken(String token) {
        return userRepo.findById(Jwt.from(token, accessTokenSecret).getUserId())
                .orElseThrow(UserNotFoundError::new);
    }

    public Login refreshAccess(String refreshToken) {
        var refreshJwt = Jwt.from(refreshToken, refreshTokenSecret);

        userRepo.findByIdAndTokensRefreshTokenAndTokensExpiredAtGreaterThan(refreshJwt.getUserId(), refreshJwt.getToken(), refreshJwt.getExpiration())
                .orElseThrow(UnauthenticatedError::new);

        return Login.of(refreshJwt.getUserId(), accessTokenSecret, refreshJwt, refreshTokenValidity);
    }

    public Boolean logout(String refreshToken) {
        var refreshJwt = Jwt.from(refreshToken, refreshTokenSecret);

        var user = userRepo.findById(refreshJwt.getUserId())
                .orElseThrow(UnauthenticatedError::new);

        var tokenIsRemoved = user.removeTokenIf(token -> Objects.equals(token.refreshToken(), refreshToken));

        if (tokenIsRemoved) {
            userRepo.save(user);
        }

        return tokenIsRemoved;
    }

    public void forgot(String email, String originUrl) {
        var token = UUID.randomUUID().toString().replace("-", "");
        var user = userRepo.findByEmail(email)
                .orElseThrow(UserNotFoundError::new);
        user.addPasswordRecovery(new PasswordRecovery(token));

        mailService.sendForgotMessage(email, token, originUrl);

        userRepo.save(user);
    }
}
