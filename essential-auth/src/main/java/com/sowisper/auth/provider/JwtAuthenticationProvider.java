package com.sowisper.auth.provider;

import com.sowisper.auth.pojo.vo.UserLoginVO;
import com.sowisper.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class JwtAuthenticationProvider implements AuthenticationProvider {
    @Lazy
    @Autowired
    private UserService userService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = String.valueOf(authentication.getPrincipal());
        String password = String.valueOf(authentication.getCredentials());

        UserLoginVO user = userService.getUserInfoByUsername(username);
        if(passwordEncoder.matches(password,user.getPassword())){
            return new UsernamePasswordAuthenticationToken(username, password, user.getAuthorities());
        }

        throw new BadCredentialsException("Error!!");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}
