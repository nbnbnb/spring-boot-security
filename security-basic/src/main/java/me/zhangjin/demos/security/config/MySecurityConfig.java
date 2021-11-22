package me.zhangjin.demos.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                // 设置认证方式
                // 表单方式
                .formLogin()
                // 普通方式
                // http.basic()
                .and()
                // 配置授权
                .authorizeRequests()
                // 所有请求，都需要认证
                .anyRequest().authenticated();

    }
}
