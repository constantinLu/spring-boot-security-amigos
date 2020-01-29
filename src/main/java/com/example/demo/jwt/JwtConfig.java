package com.example.demo.jwt;

import com.google.common.net.HttpHeaders;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {

    private String secretKey;

    private String tokenPrefix;

    private Integer ExpirationDays;

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Integer getExpirationDays() {
        return ExpirationDays;
    }

    public void setExpirationDays(Integer expirationDays) {
        ExpirationDays = expirationDays;
    }

    @Bean
    public SecretKey secretKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }

}
