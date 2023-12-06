package org.hung.demo.exceptions;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
    ERROR(-1, "ERROR"),

    //bad request seri - 400xxx
    BAD_REQUEST(400000, "BAD_REQUEST"),

    //resource not found seri 404xxx
    RESOURCE_NOT_FOUND(404000, "RESOURCE_NOT_FOUND"),
    USER_NOT_FOUND(RESOURCE_NOT_FOUND.getCode() + 1, "USER_NOT_FOUND");


    private final int code;
    private final String message;

    ErrorCode(int code,
              String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public HttpStatus getHttpStatus() {
        try {
            return HttpStatus.valueOf(Integer.parseInt(("" + code).substring(0, 2)));
        } catch (Exception ex) {
            return null;
        }
    }
}
