package com.maizi.common.auth.config;

import com.maizi.common.auth.filter.TokenAuthFilter;
import com.maizi.common.auth.filter.TokenLoginFilter;
import com.maizi.common.auth.security.DefaultPasswordEncoder;
import com.maizi.common.auth.security.TokenLogoutHandler;
import com.maizi.common.auth.security.TokenManager;
import com.maizi.common.auth.security.UnauthEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * 核心配置类
 *
 * @author maizi
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    private DefaultPasswordEncoder defaultPasswordEncoder;
    private UserDetailsService userDetailsService;

    @Autowired
    public TokenWebSecurityConfig(UserDetailsService userDetailsService, DefaultPasswordEncoder defaultPasswordEncoder, TokenManager tokenManager, RedisTemplate redisTemplate) {
        this.userDetailsService = userDetailsService;
        this.defaultPasswordEncoder = defaultPasswordEncoder;
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }

    /**
     * 调用userDetailsService和密码处理
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(defaultPasswordEncoder);
    }


    /**
     * 配置设置
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling()
                //没有权限访问
                .authenticationEntryPoint(new UnauthEntryPoint())
                //csrf
                .and().csrf().disable()
                //不通过Session获取SecurityContext
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                //
                .and().authorizeRequests().anyRequest().authenticated()
                //设置退出的地址
                .and().logout().logoutUrl("/admin/acl/index/logout")
                //
                .addLogoutHandler(new TokenLogoutHandler(tokenManager, redisTemplate)).and()
                //设置退出的地址和token，redis操作地址
                .addFilter(new TokenLoginFilter(authenticationManager(), tokenManager, redisTemplate))
                //设置redis操作地址
                .addFilter(new TokenAuthFilter(authenticationManager(), tokenManager, redisTemplate)).httpBasic();
    }


    /**
     * 不进行认证的路径，可以直接访问
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/api/**");
    }
}