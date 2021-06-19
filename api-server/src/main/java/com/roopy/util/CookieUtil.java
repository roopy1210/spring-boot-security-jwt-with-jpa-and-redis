package com.roopy.util;

import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Calendar;

@Service
public class CookieUtil {

    public Cookie createCookie(String cookieName, String token, String cookieDvcd) {
        Cookie cookie = new Cookie(cookieName, token);
        cookie.setHttpOnly(true);

        if ("A".equals(cookieDvcd)) {
            // 30분 = 60 * 30
            cookie.setMaxAge(60*2);
        }
        else {
            // 3시간 = 60 * 60 * 3
            cookie.setMaxAge(60*5);
        }
        cookie.setPath("/");

        return cookie;
    }

    public Cookie getCookie(HttpServletRequest request, String cookieName) {
        final Cookie[] cookies = request.getCookies();

        if (null == cookies) return null;

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(cookieName))
                return  cookie;
        }

        return null;
    }

}
