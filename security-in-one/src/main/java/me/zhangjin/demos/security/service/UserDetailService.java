package me.zhangjin.demos.security.service;

import me.zhangjin.demos.security.entity.MyUser;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@Configuration
public class UserDetailService implements UserDetailsService {

    // 默认的实现 BCryptPasswordEncoder
    private final PasswordEncoder passwordEncoder;

    public UserDetailService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // 每次登录时，都会根据 username 来获取 UserDetails
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 模拟一个用户，替代数据库获取逻辑
        // 真正的应用中会根据数据中的查询得知
        MyUser user = new MyUser();
        user.setUserName(username);
        // 存储的密码都是哈希计算过的
        // 用户输入的密码，经过同样的哈希算法，与存储的密码进行比较
        user.setPassword(this.passwordEncoder.encode("123456"));

        // 输出加密后的密码
        System.out.println("BCryptPasswordEncoder: " + user.getPassword());

        // 授权
        List<GrantedAuthority> authorities;

        if (StringUtils.equalsIgnoreCase("admin", username)) {
            authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("admin");
        } else {
            authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("test");
        }

        return new User(username, user.getPassword(), user.isEnabled(),
                user.isAccountNonExpired(), user.isCredentialsNonExpired(),
                user.isAccountNonLocked(), authorities);

    }

}
