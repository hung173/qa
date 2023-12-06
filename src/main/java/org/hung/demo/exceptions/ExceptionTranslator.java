package org.hung.demo.exceptions;

import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@ControllerAdvice
public class ExceptionTranslator extends ResponseEntityExceptionHandler {

    @Value("${application.minimize-stacktrace: true}")
    Boolean minimizeStacktrace;

    private ResponseEntity<Object> error(int code,
                                         String msg,
                                         Map<String, Object> errors,
                                         HttpStatus status) {
        CommonException data = new CommonException(code, msg, errors);
        return new ResponseEntity<>(data, status);
    }

    private ResponseEntity<Object> error(int code,
                                         String msg,
                                         HttpStatus status) {
        CommonException data = new CommonException(code, msg, new HashMap<>());
        return new ResponseEntity<>(data, status);
    }

    private ResponseEntity<Object> badRequest(String msg) {
        return error(ErrorCode.BAD_REQUEST.getCode(), msg, HttpStatus.BAD_REQUEST);
    }

    private void minimizeStacktrace(Exception ex) {
        // Nếu last trace là code  của project thì chỉ cần in vf package, còn không thì in stacktrace
        // log dashboard đang ko hỗ trợ multiline.
        StackTraceElement last = ex.getStackTrace()[0];
        if (last.getClassName().contains("org.hung")) {
            StackTraceElement[] traces = ex.getStackTrace();
            StringBuilder error = new StringBuilder("error : ").append(ex.getMessage()).append(" at : ");
            for (StackTraceElement trace : traces) {
                if (trace.getClassName().contains("org.hung")) {
                    error
                            .append(trace.getClassName())
                            .append(".")
                            .append(trace.getMethodName())
                            .append(" line : ")
                            .append(trace.getLineNumber())
                            .append(";");
                }
            }
            log.error(error.toString());
        } else {
            log.error("Error : ", ex);
        }
    }

    private void logError(Exception ex) {
        if (minimizeStacktrace) {
            minimizeStacktrace(ex);
        } else {
            log.error("Error : ", ex);
        }
    }

    private void logError(String error) {
        log.error("Error : {}", error);
    }

    @ExceptionHandler(value = CommonException.class)
    public ResponseEntity<?> handleCommonException(CommonException exception) {
        log.debug("handleCommonException");
        logError(exception);
        return error(exception.getCode(), exception.getMessage(), exception.getErrors(), exception.getHttpStatus());
    }

    @ExceptionHandler(value = DataIntegrityViolationException.class)
    public ResponseEntity<?> handleDataIntegrityViolationException(DataIntegrityViolationException exception) {
        log.debug("handleDataIntegrityViolationException");
        logError(exception);
        return error(ErrorCode.BAD_REQUEST.getCode(), "Can't update/delete", null, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(value = Exception.class)
    public ResponseEntity<?> handleInternalException(Exception exception) {
        log.debug("handleInternalException");
        logError(exception);
        if (exception instanceof RuntimeException) {
            if (exception.getMessage() != null && exception.getMessage().contains("UT000036")) return badRequest(
                    ErrorCode.BAD_REQUEST.getMessage()
            );
        }
        return error(ErrorCode.ERROR.getCode(), ErrorCode.ERROR.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler({ConstraintViolationException.class, MultipartException.class})
    public ResponseEntity<Object> handleConstraintViolation(Exception ex) {
        log.debug("handleConstraintViolation");
        logError(ex.getMessage());
        return badRequest(ErrorCode.BAD_REQUEST.getMessage());
    }

//    @ExceptionHandler(MaxUploadSizeExceededException.class)
//    public ResponseEntity<Object> handleUploadFileSizeException(MaxUploadSizeExceededException ex) {
//        log.debug("handleUploadFileSizeException");
//        logError(ex.getMessage());
//        return badRequest("Maximum upload size exceeded");
//    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {
        log.debug("handleMethodArgumentNotValid");
        logError(ex);
        FieldError fieldError = ex.getBindingResult().getFieldError();
        String errorMsg = "invalid field " + fieldError.getField() + ":" + fieldError.getDefaultMessage();
        return badRequest(errorMsg);
    }

}
