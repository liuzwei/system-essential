package com.sowisper.auth.service;

import cn.hutool.jwt.JWT;
import com.sowisper.auth.pojo.vo.UserLoginVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 根据账号查询用户信息
     * @param username
     * @return
     */
    public UserLoginVO getUserInfoByUsername(String username) {
        UserLoginVO user = null;
        if ("admin".equals(username)) {
            user = new UserLoginVO();
            user.setUsername("admin");
            user.setPassword("$2a$10$m/65.gGwgC0Dc9dUUxRgRu5F/fkyakVJJfQkG1TnUuhDitjaI9Z8K");
            List<UserLoginVO.UserGrantedAuthority> authorities = new ArrayList<UserLoginVO.UserGrantedAuthority>();
            authorities.add(new UserLoginVO.UserGrantedAuthority("ROLE_ADMIN"));
            user.setAuthorities(authorities);

            return user;
        }
        Assert.notNull(user, () -> "UserDetailsService returned null for username " + username
                + ". " + "This is an interface contract violation");
        return null;
    }

    public String login(String username, String password) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        // 交由authenticationManager去校验用户名和密码是否正确
        authenticationManager.authenticate(authenticationToken);

        //上一步没有抛出异常说明认证成功，我们向用户颁发jwt令牌
        String token = JWT.create()
                .setPayload("username", username)
                .setKey("My_key".getBytes(StandardCharsets.UTF_8))
                .sign();

        return token;
    }
}
