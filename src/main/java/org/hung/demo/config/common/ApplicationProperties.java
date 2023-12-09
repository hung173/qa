package org.hung.demo.config.common;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "application", ignoreUnknownFields = false)
@Data
public class ApplicationProperties {

    private final WebsocketProperties websocket = new WebsocketProperties();

    @Data
    public static class WebsocketProperties {
        private String endpoint;
        private String brokerTopicPrefix;
        private String clientTopicPrefix;
    }
}
