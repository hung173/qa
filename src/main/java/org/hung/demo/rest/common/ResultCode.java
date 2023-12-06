package org.hung.demo.rest.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
@Accessors(chain = true)
@JsonInclude(value = Include.NON_NULL)
public class ResultCode {
	private int code;
	
	private String message;
	
	private Map<String, Object> metadata = null;
	
	public ResultCode(int code, String message) {
		this.code = code;
		this.message = message;
	}
	
	public ResultCode(int code, String message, Map<String, Object> metadata) {
		this.code = code;
		this.message = message;
		this.metadata = metadata;
	}
	
	public ResultCode(int code, String message, String key, Object value) {
		this.code = code;
		this.message = message;
		this.metadata = new HashMap<>();
		this.metadata.put(key, value);
	}
}

