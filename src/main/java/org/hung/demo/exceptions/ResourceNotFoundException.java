package org.hung.demo.exceptions;

import org.springframework.http.HttpStatus;

public class ResourceNotFoundException extends CommonException {

    public ResourceNotFoundException(int code, String message) {
        super(code, message, HttpStatus.NOT_FOUND);
    }

    public ResourceNotFoundException(String message) {
        this(ErrorCode.RESOURCE_NOT_FOUND.getCode(), message);
    }

    public ResourceNotFoundException(ErrorCode errorCode) {
        super(errorCode);
    }
}
