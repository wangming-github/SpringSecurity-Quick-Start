package com.maizi.auth.center.security;

import com.maizi.common.core.utils.R;
import com.maizi.common.core.utils.ResponseUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * 退出处理器
 *
 * @author maizi
 */
@Data
@Slf4j
@Component
public class TokenLogoutHandler implements LogoutHandler {

    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;


    public TokenLogoutHandler(TokenManager tokenManager, RedisTemplate redisTemplate) {
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
        //1 从header里面获取token
        //2 token不为空，移除token，从redis删除token
        String token = httpServletRequest.getHeader("token");

        if (token != null) {
            //移除
            tokenManager.removeToken(token);
            //从token中获取用户名
            String username = tokenManager.getUserInfoByToken(token);
            //删除redis中的token
            redisTemplate.delete(username);
            log.info("删除redis中的token:{}", username);
        }
        ResponseUtil.out(httpServletResponse, R.ok());
    }
}
