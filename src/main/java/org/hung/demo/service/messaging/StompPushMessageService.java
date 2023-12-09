package org.hung.demo.service.messaging;

import lombok.extern.slf4j.Slf4j;
import org.hung.demo.model.PushMessage;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class StompPushMessageService implements PushMessageService {

    private final SimpMessagingTemplate simpMessagingTemplate;

    public StompPushMessageService(SimpMessagingTemplate simpMessagingTemplate) {
        this.simpMessagingTemplate = simpMessagingTemplate;
    }

    @Override
    public void pushMessage(PushMessage message,
                            String topic) {
        log.debug("send message :{} to topic : {}", message, topic);
        simpMessagingTemplate.convertAndSend(topic, message);
    }
}
