package com.paascloud.security.core.bootsocial;

import org.springframework.core.env.Environment;
import org.springframework.social.UserIdSource;
import org.springframework.social.config.annotation.ConnectionFactoryConfigurer;
import org.springframework.social.config.annotation.SocialConfigurerAdapter;
import org.springframework.social.connect.ConnectionFactory;
import org.springframework.social.security.AuthenticationNameUserIdSource;

/**
 * Base class for auto-configured {@link SocialConfigurerAdapter}s.
 *
 * @author Craig Walls
 * @author Phillip Webb
 * @since 1.4.0
 */
public abstract class SocialAutoConfigurerAdapter extends SocialConfigurerAdapter {

    @Override
    public void addConnectionFactories(ConnectionFactoryConfigurer configurer,
                                       Environment environment) {
        configurer.addConnectionFactory(createConnectionFactory());
    }

    @Override
    public UserIdSource getUserIdSource() {
        return new AuthenticationNameUserIdSource();
    }

    protected abstract ConnectionFactory<?> createConnectionFactory();

}
