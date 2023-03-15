package com.example.userservice.security;

import com.example.userservice.filter.CustomAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder encoder;

    // authenticationManager 에서 사용할 UserDetailsService 객체를 인자로 받아
    // DAO authenticationConfigurer 를 반환 받으면 그 안에 passwordEncoder 를 지정해줌
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(encoder);
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // csrf 금지
        http.csrf().disable();
        // http 프로토콜의 조건 중 하나인 STATELESS 무상태 구조
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // ExpressionInterceptUrlRegistry 를 통해 각각 url 로의 접근 권한을 설정할 수 있게 해줌 
        http.authorizeRequests()
                // 특정한 Request url 외에 모든 url 에 어떤 권한이든 permit 해줌
                .anyRequest().permitAll();
        // filter 로 dispatcher servlet 에 접근하기 전에 먼저 authenticationManager 객체로 검사
        http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));
    }

    // CustomFilter 에 사용할 AuthenticationManager 를 제공하기 위해 빈 생성
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
