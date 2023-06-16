package com.sowisper.auth.pojo.vo;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * 用户登录相关信息
 */
@Data
public class UserLoginVO {

    private String id;

    private String username;

    private String password;

    Collection<UserGrantedAuthority> authorities;

    @Data
    public static class UserGrantedAuthority implements GrantedAuthority {

        /**
         * 用户角色
         */
        private String role;

        public UserGrantedAuthority(String role) {
            this.role = role;
        }

        @Override
        public String getAuthority() {
            return this.role;
        }
    }
}
