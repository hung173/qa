package org.hung.demo.model;

import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
public class PushMessage<T> {
    T payload;
    Map<String, String> metadata = new HashMap<>();
}
