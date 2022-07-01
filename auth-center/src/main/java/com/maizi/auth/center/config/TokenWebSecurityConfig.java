package com.maizi.auth.center.config;

import com.maizi.auth.center.filter.TokenAuthFilter;
import com.maizi.auth.center.filter.TokenLoginFilter;
import com.maizi.auth.center.security.DefaultPasswordEncoder;
import com.maizi.auth.center.security.TokenLogoutHandler;
import com.maizi.auth.center.security.TokenManager;
import com.maizi.auth.center.security.UnauthEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
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
@ComponentScan("com.maizi.auth.center")
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private TokenManager tokenManager;
    private DefaultPasswordEncoder defaultPasswordEncoder;

    private RedisTemplate redisTemplate;
    private UserDetailsService userDetailsService;

    public TokenWebSecurityConfig(TokenManager tokenManager, DefaultPasswordEncoder defaultPasswordEncoder, RedisTemplate redisTemplate, UserDetailsService userDetailsService) {
        this.tokenManager = tokenManager;
        this.defaultPasswordEncoder = defaultPasswordEncoder;
        this.redisTemplate = redisTemplate;
        this.userDetailsService = userDetailsService;
    }

    /**
     * 配置设置
     * 设置退出的地址和token，redis操作地址
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();

        //没有权限访问时调用自己指定的处理流程
        http.exceptionHandling().authenticationEntryPoint(new UnauthEntryPoint());

        //
        http.authorizeRequests().anyRequest().authenticated();

        //不通过Session获取SecurityContext
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        //退出路径
        http.logout().logoutUrl("/logout").addLogoutHandler(new TokenLogoutHandler(tokenManager, redisTemplate));
        //添加登录过滤器
        http.addFilter(new TokenLoginFilter(authenticationManager(), tokenManager, redisTemplate));
        //添加授权过滤器
        http.addFilter(new TokenAuthFilter(authenticationManager(), tokenManager, redisTemplate));

        //httpBasic认证
        http.httpBasic();
    }

    /**
     * 调用userDetailsService和密码处理
     *
     * @param auth
     * @throws Exception
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                //调用自定义的MD5加密方法
                .passwordEncoder(defaultPasswordEncoder);
    }

    /**
     * 不进行认证的路径，可以直接访问
     *
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/api/**");
    }
}