package com.roopy.service;

import com.roopy.AuthServerApplication;
import com.roopy.security.jwt.payload.request.LoginRequest;
import com.roopy.security.jwt.payload.response.TokenResponse;
import org.junit.Assert;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = AuthServerApplication.class)
public class AuthServiceTest {

    @Autowired
    private AuthService authService;

    /**
     * 정상적인 사용자 정보에 대한 테스트
     */
    @Test
    public void testSuccessGenerateAccessTokenAndRefreshToken() throws Exception {
        LoginRequest request = LoginRequest.builder()
                                    .username("admin")
                                    .password("admin")
                                    .build();

        TokenResponse tokenResponse = authService.generateAccessTokenAndRefreshToken(request);
        Assert.assertNotNull(tokenResponse);
    }

    /**
     * 비정상적인 사용자 정보에 대한 테스트
     */
    @Test
    public void testFailGenerateAccessTokenAndRefreshToken() {
        LoginRequest request = LoginRequest.builder()
                .username("admin")
                .password("admin1")
                .build();

        Assertions.assertThrows(AuthenticationException.class
                , () -> authService.generateAccessTokenAndRefreshToken(request)
                , "사용자 정보가 올바르지 않습니다.");
    }
}
