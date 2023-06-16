package com.sowisper.auth.config;


import com.sowisper.auth.filter.JwtAccessDeniedHandler;
import com.sowisper.auth.filter.JwtAuthenticationTokenFilter;
import com.sowisper.auth.filter.JwtUnauthorizedHandler;
import com.sowisper.auth.provider.JwtAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @EnableMethodSecurity 开发方法级别授权校验
 */
@EnableMethodSecurity
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtUnauthorizedHandler jwtUnauthorizedHandler;
    @Autowired
    private JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //自定义的拦截器
    @Bean
    public JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter() {
        return new JwtAuthenticationTokenFilter();
    }

    // 登录认证处理逻辑，判断用户名密码是否正确
    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider() {
        return new JwtAuthenticationProvider();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        //基于token，所以不需要csrf防护
        httpSecurity.csrf().disable()
                //基于token，所以不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests( requests -> requests
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/register").permitAll()
                        .anyRequest().authenticated()
                );
        //禁用缓存
        httpSecurity.headers().cacheControl();
        httpSecurity.authenticationProvider(jwtAuthenticationProvider());
        //将我们的JWT filter添加到UsernamePasswordAuthenticationFilter前面，因为这个Filter是authentication开始的filter，我们要早于它
        httpSecurity.addFilterBefore(jwtAuthenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        // 认证异常处理
        httpSecurity.exceptionHandling().authenticationEntryPoint(jwtUnauthorizedHandler);
        // 授权失败处理
        httpSecurity.exceptionHandling().accessDeniedHandler(jwtAccessDeniedHandler);

        return httpSecurity.build();
    }
}
