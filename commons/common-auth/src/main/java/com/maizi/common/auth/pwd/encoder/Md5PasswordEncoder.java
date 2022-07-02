package com.maizi.common.auth.pwd.encoder;

import com.maizi.common.core.utils.MD5;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;


/**
 * 密码处理
 *
 * @author maizi
 */
@Component
public class Md5PasswordEncoder implements PasswordEncoder {

    @Override
    public String encode(CharSequence charSequence) {
        return MD5.encrypt(charSequence.toString());
    }

    @Override
    public boolean matches(CharSequence charSequence, String encodedPassword) {

        return encodedPassword.equals(MD5.encrypt(charSequence.toString()));
    }
}
