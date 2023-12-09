package org.hung.demo.config.websocket;

import org.hung.demo.config.common.ApplicationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    private final String stompEndpoint;

    private final String brokerTopicPrefix;

    private final String clientTopicPrefix;

    public WebSocketConfig(ApplicationProperties applicationProperties) {
        var websocketProperties = applicationProperties.getWebsocket();
        this.stompEndpoint = websocketProperties.getEndpoint();
        this.brokerTopicPrefix = websocketProperties.getBrokerTopicPrefix();
        this.clientTopicPrefix = websocketProperties.getClientTopicPrefix();
    }


    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config.enableSimpleBroker(brokerTopicPrefix);
        config.setApplicationDestinationPrefixes(clientTopicPrefix);
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint(stompEndpoint);
    }
}
