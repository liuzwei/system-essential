package com.sowisper.auth.filter;

import cn.hutool.jwt.JWTUtil;
import com.sowisper.auth.pojo.vo.UserLoginVO;
import com.sowisper.auth.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    private UserService userService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (Objects.isNull(authHeader) || !authHeader.startsWith("Bearer")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 获取到token
        String authToken = authHeader.split(" ")[1];

        // 验证token
        if (!JWTUtil.verify(authToken, "My_key".getBytes(StandardCharsets.UTF_8))) {
            filterChain.doFilter(request, response);
            return;
        }

        // 解析token
        String username = (String) JWTUtil.parseToken(authToken).getPayload("username");
        // 根据账号查询用户信息
        UserLoginVO user = userService.getUserInfoByUsername(username);

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(username, user.getPassword(), user.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        //将认证过了凭证保存到security的上下文中以便于在程序中使用
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }
}
