package org.hung.demo.exceptions;

import org.springframework.http.HttpStatus;

public class BadRequestException extends CommonException {

    public BadRequestException(int code, String message) {
        super(code, message, HttpStatus.BAD_REQUEST);
    }

    public BadRequestException(String message) {
        this(ErrorCode.BAD_REQUEST.getCode(), message);
    }

    public BadRequestException(ErrorCode errorCode) {
        super(errorCode);
    }
}
