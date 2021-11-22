package com.zjh.security.config;


import com.zjh.security.fileter.ValidateCodeFilter;
import com.zjh.security.handler.MyAuthenticationAccessDeniedHandler;
import com.zjh.security.handler.MyAuthenticationFailureHandler;
import com.zjh.security.handler.MyAuthenticationSuccessHandler;
import com.zjh.security.service.UserDetailService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;

@Component
// 开启权限注解
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private MyAuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private ValidateCodeFilter validateCodeFilter;

    @Autowired
    private UserDetailService userDetailService;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private MyAuthenticationAccessDeniedHandler myAuthenticationAccessDeniedHandler;

    // 需要 persistent_logins 表
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        // 是否在启动时重建表，调试时使用
        // 查看源码，里面有对应的 SQL 建表语句
        jdbcTokenRepository.setCreateTableOnStartup(false);
        return jdbcTokenRepository;
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                // 在 UsernamePasswordAuthenticationFilter 执行前
                // 添加自定义的 ValidateCodeFilter 验证码 Filter
                .addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
                // 使用默认的异常处理器
                .exceptionHandling()
                // 使用自定义的拒绝访问处理器
                .accessDeniedHandler(myAuthenticationAccessDeniedHandler)
                .and()
                // 设置登录类型
                // 表单登录
                .formLogin()
                // HTTP Basic 登录
                // http.httpBasic()
                //
                // 设置登录跳转 URL
                .loginPage("/login.html")
                // 处理表单登录 URL，也就是登录 POST 的 URL
                .loginProcessingUrl("/login")
                // 登录失败处理器（响应错误代码）
                .failureHandler(authenticationFailureHandler)
                // 登录成功处理器（跳转到首页）
                .successHandler(authenticationSuccessHandler)
                .and()
                // 杂项功能
                // 启用 rememberMe
                .rememberMe()
                // 配置 token 持久化仓库
                .tokenRepository(persistentTokenRepository())
                // remember 过期时间，单为秒
                .tokenValiditySeconds(3600)
                // 处理自动登录逻辑
                .userDetailsService(userDetailService)
                .and()
                // 下面对页面进行配置授权
                .authorizeRequests()
                // 特定 URL，无需认证
                .antMatchers("/authentication/require", "/login.html", "/code/image").permitAll()
                // 所有请求，都需要认证
                .anyRequest().authenticated()
                .and()
                // 禁用 CSRF
                .csrf().disable();
    }
}
