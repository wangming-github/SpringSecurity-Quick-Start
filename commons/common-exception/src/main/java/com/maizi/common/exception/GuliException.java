package com.maizi.common.exception;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author maizi
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class GuliException extends RuntimeException {

    /**
     * 状态码
     */
    private Integer code;
    /**
     * 异常信息
     */
    private String msg;
}
