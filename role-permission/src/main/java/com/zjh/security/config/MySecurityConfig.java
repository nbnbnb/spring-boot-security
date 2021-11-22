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
@EnableGlobalMethodSecurity(prePostEnabled = true) // 开启权限注解
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    private final MyAuthenticationFailureHandler authenticationFailureHandler;

    private final MyAuthenticationSuccessHandler authenticationSuccessHandler;

    private final ValidateCodeFilter validateCodeFilter;

    private final UserDetailService userDetailService;

    private final DataSource dataSource;

    private final MyAuthenticationAccessDeniedHandler myAuthenticationAccessDeniedHandler;

    public MySecurityConfig(MyAuthenticationFailureHandler authenticationFailureHandler,
                            MyAuthenticationSuccessHandler authenticationSuccessHandler,
                            ValidateCodeFilter validateCodeFilter,
                            UserDetailService userDetailService,
                            DataSource dataSource,
                            MyAuthenticationAccessDeniedHandler myAuthenticationAccessDeniedHandler) {

        this.authenticationFailureHandler = authenticationFailureHandler;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.validateCodeFilter = validateCodeFilter;
        this.userDetailService = userDetailService;
        this.dataSource = dataSource;
        this.myAuthenticationAccessDeniedHandler = myAuthenticationAccessDeniedHandler;

    }


    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        jdbcTokenRepository.setCreateTableOnStartup(false);
        return jdbcTokenRepository;
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加验证码校验过滤器
                .exceptionHandling()
                .accessDeniedHandler(myAuthenticationAccessDeniedHandler)
                .and()
                .formLogin() // 表单登录
                // http.httpBasic() // HTTP Basic
                .loginPage("/authentication/require") // 登录跳转 URL
                .loginProcessingUrl("/login") // 处理表单登录 URL
                .failureHandler(authenticationFailureHandler) // 处理登录失败
                .successHandler(authenticationSuccessHandler) // 登录成功
                .and()
                .rememberMe() // 启用 rememberMe
                .tokenRepository(persistentTokenRepository()) // 配置 token 持久化仓库
                .tokenValiditySeconds(3600) // remember 过期时间，单为秒
                .userDetailsService(userDetailService) // 处理自动登录逻辑
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
