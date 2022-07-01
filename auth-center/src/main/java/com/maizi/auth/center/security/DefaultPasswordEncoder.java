package com.maizi.auth.center.security;

import com.maizi.common.core.utils.MD5;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;


/**
 * 密码处理
 *
 * @author maizi
 */

@Component
public class DefaultPasswordEncoder implements PasswordEncoder {


    /**
     * 对数据进行MD5加密
     */
    @Override
    public String encode(CharSequence charSequence) {
        return MD5.encrypt(charSequence.toString());
    }

    /**
     * 进行密码比对
     *
     * @param charSequence   明文密码
     * @param encodePassword 加密后的密码
     */
    @Override
    public boolean matches(CharSequence charSequence, String encodePassword) {
        return encodePassword.equals(MD5.encrypt(charSequence.toString()));
    }


    public static void main(String[] args) {
        DefaultPasswordEncoder encoder = new DefaultPasswordEncoder();
        System.out.println(encoder.encode("123"));


    }
}