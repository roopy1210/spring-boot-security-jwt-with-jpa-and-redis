package com.roopy.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.roopy.crypto.AES256Cipher;
import com.roopy.security.jwt.payload.request.LoginRequest;
import com.roopy.security.jwt.payload.response.TokenResponse;
import com.roopy.util.CookieUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.HashMap;

@RestController
public class LoginController {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private CookieUtil cookieUtil;

    @Value("${jwt.access-token-cookie-name}")
    private String accessTokenCookieName;

    @Value("${jwt.refresh-token-cookie-name}")
    private String refreshTokenCookieName;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(HttpServletRequest httpServletRequest
            , HttpServletResponse httpServletResponse
            , @Valid @RequestBody LoginRequest loginRequest) throws Exception {

        CookieUtil cookieUtil = new CookieUtil();

        // 토큰 발행 요청
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ObjectMapper mapper = new ObjectMapper();

        HttpEntity<String> request = new HttpEntity<>(mapper.writeValueAsString(loginRequest), headers);
        ResponseEntity<HashMap> responseEntity = restTemplate.postForEntity( "http://localhost:10001/token/issue", request , HashMap.class );

        // 토큰 발행 요청 결과
        String accessToken = null;
        String refreshToken = null;

        Cookie accessTokenCookie = null;
        Cookie refreshTokenCookie = null;

        if (responseEntity.getStatusCodeValue() == HttpStatus.OK.value()) {
            accessToken = (String) responseEntity.getBody().get("accessToken");
            refreshToken = (String) responseEntity.getBody().get("refreshToken");

            // AccessToken 쿠키 저장
            accessTokenCookie = cookieUtil.createCookie(accessTokenCookieName, accessToken, "A");

            // RefreshToken 쿠키 저장
            refreshTokenCookie = cookieUtil.createCookie(refreshTokenCookieName, AES256Cipher.encrypt(refreshToken), "R");

            httpServletResponse.addCookie(accessTokenCookie);
            httpServletResponse.addCookie(refreshTokenCookie);
        }

        return new ResponseEntity<>(new TokenResponse(accessToken), HttpStatus.OK);
    }
}
