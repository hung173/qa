package org.hung.demo.service.messaging;

import org.hung.demo.model.PushMessage;

interface PushMessageService {

    void pushMessage(PushMessage message, String topic);
}
