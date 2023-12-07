package org.hung.demo.common;

public final class Constants {

    private Constants() {

    }

    public static final class Authority {
        public static final String ROLE_SYSTEM = "SYSTEM";
        public static final String ROLE_ADMIN = "ADMIN";
        public static final String ROLE_USER = "USER";
        public static final String ROLE_ANONYMOUS = "ANONYMOUS";
        public static final String AUTHORITY_CLAIM = "authorities";
        public static final String ATTRIBUTE_CONSTANT = "sub";
    }
}
