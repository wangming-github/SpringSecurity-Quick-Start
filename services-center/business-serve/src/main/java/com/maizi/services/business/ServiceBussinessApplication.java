package com.maizi.services.business;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * @author maizi
 * 注释 @ComponentScan("com.maizi") 缺少此注释识别不到其他模块的SpringSecurity
 */
@SpringBootApplication
@EnableDiscoveryClient
@EnableWebSecurity
@ComponentScan("com.maizi")
@MapperScan("com.maizi.services.business.mapper")
public class ServiceBussinessApplication {

    public static void main(String[] args) {
        SpringApplication.run(ServiceBussinessApplication.class, args);
    }

}
