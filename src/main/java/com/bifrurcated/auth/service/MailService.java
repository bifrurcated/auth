package com.bifrurcated.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
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

        MimeMessagePreparator message = mimeMessage -> {
            MimeMessageHelper msg = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            msg.setFrom("noreply@bifrurcated.com");
            msg.setTo(email);
            msg.setSubject("Reset your password");
            msg.setText(String.format("Click <a href=\"%s/api/reset/%s\">here</a> to reset your password.", url, token), true);
        };

        javaMailSender.send(message);
    }
}
