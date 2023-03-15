package com.example.userservice.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Log4j2
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // authentication 을 하기 위한 관리자객체 생성
    public CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }
    // authentication 에 사용하기 위해 username 과 password 를 이용하여
    // UsernamePasswordAuthenticationToken 객체 생성
    // 로그인 실패시 AuthenticationException 전달
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username : {} , Password : {}",username, password);
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(username, password);
        // 관리자 객체에 인증 토큰을 인자로 담아 반환
        return authenticationManager.authenticate(authenticationToken);
    }

    // 로그인에 계속 실패할 경우 사용하기 위한 authentication 성공 메소드
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            // AuthenticationManager 가 인증한 로그인 결과
                                            // = attemptAuthentication() 의 반환 값
                                            Authentication authResult) throws IOException, ServletException {
        
    }
}
