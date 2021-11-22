package com.zjh.security.captcha;

import lombok.Data;

import java.awt.image.BufferedImage;
import java.time.LocalDateTime;


@Data
public class ImageCode {

    private BufferedImage image;

    private String code;

    private LocalDateTime expireTime;

    public ImageCode(BufferedImage image, String code, int expireIn) {
        this.image = image;
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireIn);
    }

    public ImageCode(BufferedImage image, String code, LocalDateTime expireTime) {
        this.image = image;
        this.code = code;
        this.expireTime = expireTime;
    }

    // 过期时间
    public boolean isExpire() {
        return LocalDateTime.now().isAfter(expireTime);
    }

    @Override
    public String toString() {
        return "ImageCode{" +
                "image=" + image +
                ", code='" + code + '\'' +
                ", expireTime=" + expireTime +
                '}';
    }

}
