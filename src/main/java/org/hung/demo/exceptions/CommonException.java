package org.hung.demo.exceptions;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

@JsonIgnoreProperties(value = { "stackTrace", "cause", "suppressed", "localizedMessage" })
public class CommonException extends RuntimeException {

    private int code = 500;
    private HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
    private Map<String, Object> errors = new HashMap<>();

    public CommonException(String message) {
        super(message);
    }

    public CommonException(int code,
                           String message) {
        this(message);
        this.code = code;
    }

    public CommonException(String message,
                           HttpStatus httpStatus) {
        this(message);
        this.httpStatus = httpStatus;
    }

    public CommonException(int code,
                           String message,
                           HttpStatus httpStatus) {
        this(code, message);
        this.httpStatus = httpStatus;
    }

    public CommonException(int code,
                           String message,
                           Map<String, Object> errors) {
        this(code, message);
        this.errors = errors;
    }

    public CommonException(int code,
                           String message,
                           HttpStatus httpStatus,
                           Map<String, Object> errors) {
        this(code, message, httpStatus);
        this.errors = errors;
    }

    public CommonException(ErrorCode errorCode) {
        this(
                errorCode.getCode(),
                errorCode.getMessage(),
                errorCode.getHttpStatus() != null ? errorCode.getHttpStatus() : HttpStatus.BAD_REQUEST
        );
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public Map<String, Object> getErrors() {
        return errors;
    }

    public void setErrors(Map<String, Object> errors) {
        this.errors = errors;
    }
}
