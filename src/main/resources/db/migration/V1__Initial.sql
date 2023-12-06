CREATE TABLE users(
                      id         int4    NOT NULL GENERATED ALWAYS AS IDENTITY,
                      username   varchar NOT NULL,
                      "password" varchar NULL,
                      first_name varchar NULL,
                      last_name  varchar NULL,
                      email      varchar NULL,
                      user_type  varchar NULL,
                      status  varchar NOT NULL DEFAULT 'ACTIVE',
                      is_active boolean NOT NULL DEFAULT true,
                      created_by varchar(50) NULL,
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
INSERT INTO public.users (username,"password",first_name,last_name,email,user_type,status,is_active,created_by,created_date,last_modified_by,last_modified_date) VALUES
    ('admin','$2a$12$IXGFMoGXC6v4BVSllNH3Z.9hE.24K5K2k70XQt7HOK0/HEjI.Eo8.','admin','admin','admin@admin.com','LOCAL','ACTIVE',true,'admin',NULL,NULL,NULL);