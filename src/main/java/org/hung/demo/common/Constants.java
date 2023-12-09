package org.hung.demo.common;

import org.springframework.data.domain.Sort;

public final class Constants {

    private Constants() {

    }

    public static final class Authority {
        private Authority() {
        }

        public static final String ROLE_SYSTEM = "SYSTEM";
        public static final String ROLE_ADMIN = "ADMIN";
        public static final String ROLE_USER = "USER";
        public static final String ROLE_ANONYMOUS = "ANONYMOUS";
        public static final String AUTHORITY_CLAIM = "authorities";
        public static final String ATTRIBUTE_CONSTANT = "sub";
    }

    public static final class Pagination {
        private Pagination() {

        }

        public static final int DEFAULT_PAGE = 0;
        public static final int DEFAULT_PAGE_SIZE = 20;
        public static final Sort.Direction DEFAULT_SORT_DIRECTION = Sort.Direction.DESC;
    }
}
