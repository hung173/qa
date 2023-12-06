package org.hung.demo.rest.common;


public class ResultCodes {

    public static final int COMMON_ERROR_CODE = 1000;

    public static final ResultCode SUCCESS = new ResultCode(0, "Success");

    public static final ResultCode ERROR = new ResultCode(COMMON_ERROR_CODE + 0, "Internal error");

}
