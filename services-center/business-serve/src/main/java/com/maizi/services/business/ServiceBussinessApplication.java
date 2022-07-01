package com.maizi.services.business;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * @author maizi
 */
@SpringBootApplication
@EnableDiscoveryClient
@MapperScan("com.maizi.services.business.mapper")
public class ServiceBussinessApplication {

    public static void main(String[] args) {
        SpringApplication.run(ServiceBussinessApplication.class, args);
    }

}
