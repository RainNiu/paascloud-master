package com.paascloud.security.core.bootsocial;

import lombok.Data;

@Data
public abstract class SocialProperties {

    /**
     * Application id.
     */
    private String appId;

    /**
     * Application secret.
     */
    private String appSecret;
}
