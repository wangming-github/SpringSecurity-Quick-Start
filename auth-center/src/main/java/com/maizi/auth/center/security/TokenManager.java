package com.maizi.auth.center.security;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * token管理工具类
 *
 * @author maizi
 */
@Slf4j
@Component
public class TokenManager {

    /**
     * 设置token有效时间
     */

    private final long tokenExpiration = (24 * 60 * 60 * 100) + System.currentTimeMillis();
    /**
     * token加密密钥
     */
    private final String tokenSignKey = "123456789";

    /**
     * 根据用户名生成token
     *
     * @param username username
     * @return token
     */
    public String createJwtToken(String username) {

        return Jwts.builder()
                //设置主题  可以是JSON数据
                .setSubject(username)
                //生成令牌的一方
                .setIssuer("颁发者")
                ////设置jwt的签发时间
                .setIssuedAt(new Date())
                //设置过期时间
                .setExpiration(new Date(tokenExpiration))
                //设置签名使用的签名算法和签名使用的秘钥
                .signWith(SignatureAlgorithm.HS512, tokenSignKey)
                //数据压缩方式
                .compressWith(CompressionCodecs.GZIP)
                //构建 并返回一个字符串
                .compact();

    }

    /**
     * 根据token字符串得到用户信息
     *
     * @param token token字符串
     * @return username
     */
    public String getUserInfoByToken(String token) {
        try {
            return Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody().getSubject();
        } catch (Exception e) {
            return null;
        }
    }


    /**
     * 删除token
     *
     * @param token token字符串
     * @return false/true
     */
    public boolean removeToken(String token) {

        return false;
    }


    public static void main(String[] args) {
        TokenManager tokenManager = new TokenManager();

        String token = tokenManager.createJwtToken("admin");
        log.info("TOKEN: " + token);

        String username = tokenManager.getUserInfoByToken(token);
        log.info("username: " + username);
    }
}