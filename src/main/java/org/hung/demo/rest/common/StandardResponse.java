package org.hung.demo.rest.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.minidev.json.annotate.JsonIgnore;
import org.hung.demo.rest.common.ResultCodes;
import org.springframework.data.domain.Page;

import java.util.HashMap;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class StandardResponse<T> {

    private Integer code;
    private String message;
    private T data;

    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    @JsonIgnore
    public boolean isSuccess() {
        return code == ResultCodes.SUCCESS.getCode();
    }

    public static <T> StandardResponse<T> success(T data) {
        return StandardResponse
                .<T>builder()
                .data(data)
                .message(ResultCodes.SUCCESS.getMessage())
                .code(ResultCodes.SUCCESS.getCode())
                .build();
    }

    public static <T> StandardResponse<T> successPaging(T data, Page page) {
        return StandardResponse
                .<T>builder()
                .data(data)
                .message(ResultCodes.SUCCESS.getMessage())
                .code(ResultCodes.SUCCESS.getCode())
                .metadata(page)
                .build();
    }

    public static <T> StandardResponse<T> failure() {
        return StandardResponse
                .<T>builder()
                .message(ResultCodes.ERROR.getMessage())
                .code(ResultCodes.ERROR.getCode())
                .build();
    }

    public static <T> StandardResponse<T> failure(int code, String message) {
        return StandardResponse.<T>builder().message(message).code(code).build();
    }

    public static <T> StandardResponse<T> failure(String message) {
        return StandardResponse.<T>builder().message(message).code(ResultCodes.ERROR.getCode()).build();
    }

    public static class StandardResponseBuilder<T> {

        private int code;
        private String message;
        private T data;
        private Map<String, Object> metadata = new HashMap<>();

        StandardResponseBuilder() {}

        public StandardResponseBuilder<T> code(final int code) {
            this.code = code;
            return this;
        }

        public StandardResponseBuilder<T> message(final String message) {
            this.message = message;
            return this;
        }

        public StandardResponseBuilder<T> data(final T data) {
            this.data = data;
            return this;
        }

        public StandardResponseBuilder<T> metadata(final Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public StandardResponseBuilder<T> metadata(final Page page) {
            metadata.put("total", page.getTotalElements());
            metadata.put("size", page.getSize());
            metadata.put("page", page.getNumber());
            metadata.put("totalPage", page.getTotalPages());

//            Map<String, String> sortDetails = new HashMap<>();
//            page
//                    .getSort()
//                    .iterator()
//                    .forEachRemaining(order -> sortDetails.put(order.getProperty(), order.getDirection().isAscending() ? "ASC" : "DESC"));
//            metadata.put("sort", sortDetails);
            return this;
        }

        @SuppressWarnings("all")
        public StandardResponse<T> build() {
            return new StandardResponse<T>(this.code, this.message, this.data, this.metadata);
        }

        @Override
        public String toString() {
            return (
                    "StandardResponse.StandardResponseBuilder(code=" +
                            this.code +
                            ", body=" +
                            this.message +
                            ", data=" +
                            this.data +
                            ", metadata=" +
                            this.metadata +
                            ")"
            );
        }

        @SuppressWarnings("all")
        public StandardResponse<T> buildSuccess() {
            return new StandardResponse<T>(
                    ResultCodes.SUCCESS.getCode(),
                    ResultCodes.SUCCESS.getMessage(),
                    this.data,
                    this.metadata
            );
        }

        @SuppressWarnings("all")
        public StandardResponse<T> buildSuccess(T data) {
            return new StandardResponse<T>(
                    ResultCodes.SUCCESS.getCode(),
                    ResultCodes.SUCCESS.getMessage(),
                    data,
                    this.metadata
            );
        }

        @SuppressWarnings("all")
        public StandardResponse<T> buildSuccess(T data, Map<String, Object> metadata) {
            return new StandardResponse<T>(ResultCodes.SUCCESS.getCode(), ResultCodes.SUCCESS.getMessage(), data, metadata);
        }
    }

    @SuppressWarnings("all")
    public static <T> StandardResponseBuilder<T> builder() {
        return new StandardResponseBuilder<T>();
    }
}
