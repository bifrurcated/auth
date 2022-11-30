package com.bifrurcated.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {
    private final JavaMailSender javaMailSender;
    private final String defaultFrontendUrl;

    @Autowired
    public MailService(JavaMailSender javaMailSender, @Value("${application.frontend-default-url}") String defaultFrontendUrl) {
        this.javaMailSender = javaMailSender;
        this.defaultFrontendUrl = defaultFrontendUrl;
    }

    public void sendForgotMessage(String email, String token, String baseUrl) {
        var url = baseUrl != null ? baseUrl : defaultFrontendUrl;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("noreply@bifrurcated.com");
        message.setTo(email);
        message.setSubject("Reset your password");
        message.setText(String.format("Click <a href=\"%s/api/reset/%s\">here</a> to reset your password.", url, token));

        javaMailSender.send(message);
    }
}
