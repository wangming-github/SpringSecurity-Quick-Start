package com.maizi.auth.center.filter;

import com.maizi.auth.center.security.TokenManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 授权过滤器
 * <p>
 * 登录流程：
 * 用户登录会查询username、password以及权限列表
 * 然后会执行两步：
 * 1.根据key:username、value:password将登录信息存入redis
 * 2.根据username生成token
 * 生成的token会随着登录成功放在客户端cookie中
 * <p>
 * 授权流程：
 * 页面每次请求会将此token放在header中传递到后台
 * 从header中获取username
 * 根据username从redis中查询其权限列表
 * 然后由Spring-security给用户授权
 *
 * @author maizi
 */
public class TokenAuthFilter extends BasicAuthenticationFilter {

    private TokenManager tokenManager;

    private RedisTemplate redisTemplate;

    /**
     * 已经包含了AuthenticationManager对象
     */
    public TokenAuthFilter(AuthenticationManager authenticationManager, TokenManager tokenManager, RedisTemplate redisTemplate) {
        super(authenticationManager);
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }


    /**
     * 重写框架内部的doFilterInternal
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        //获取当前认证成功用户权限信息
        UsernamePasswordAuthenticationToken authRequest = getAuthentication(request);

        //判断如果有权限信息，放到权限上下文中
        if (authRequest != null) {
            SecurityContextHolder.getContext().setAuthentication(authRequest);
        }
        //放行，执行原始流程...
        chain.doFilter(request, response);
    }

    /**
     * 获取当前认证成功用户权限信息
     */
    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {

        //从request的header中获取token
        String token = request.getHeader("token");
        if (token == null) {
            return null;
        }

        //从token中获取username
        String username = tokenManager.getUserInfoByToken(token);

        /*
         * 从redis中获取权限列表信息，转换为构建UsernamePasswordAuthenticationToken需要的类型
         */

        //从redis中获取权限列表信息
        List<String> permissionValueList = (List<String>) redisTemplate.opsForValue().get(username);
        //权限列表信息 源码Collection<? extends GrantedAuthority> authorities
        Collection<GrantedAuthority> authority = new ArrayList<>();
        permissionValueList.forEach(permission -> {
            SimpleGrantedAuthority auth = new SimpleGrantedAuthority(permission);
            authority.add(auth);
        });

        return new UsernamePasswordAuthenticationToken(username, token, authority);
    }

}