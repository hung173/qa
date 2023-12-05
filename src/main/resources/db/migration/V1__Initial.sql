CREATE TABLE users(
                      id         int4    NOT NULL GENERATED ALWAYS AS IDENTITY,
                      username   varchar NOT NULL,
                      "password" varchar NULL,
                      first_name varchar NULL,
                      last_name  varchar NULL,
                      email      varchar NULL,
                      user_type  varchar NULL,
                      is_active boolean NOT NULL DEFAULT true,
                      created_by varchar(50) NOT NULL,
                      created_date timestamp NULL,
                      last_modified_by varchar(50) NULL,
                      last_modified_date timestamp NULL,
                      CONSTRAINT user_pk PRIMARY KEY (id),
                      CONSTRAINT user_un UNIQUE (username));

CREATE TABLE authority
(
    "name" varchar NOT NULL,
    CONSTRAINT authority_pk PRIMARY KEY ("name")
);

CREATE TABLE user_authority
(
    id             int     NOT NULL,
    user_id        int     NOT NULL,
    authority_name varchar NOT NULL,
    CONSTRAINT user_authority_pk PRIMARY KEY (id),
    CONSTRAINT user_authority_fk FOREIGN KEY (id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT user_authority_fk_1 FOREIGN KEY (authority_name) REFERENCES authority ("name") ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO authority ("name") VALUES('USER'),('ADMIN');