package org.hung.demo.repository.custom;

import org.hung.demo.dto.response.UserReportResponse;
import org.hung.demo.tables.UserAuthority;
import org.hung.demo.tables.Users;
import org.jooq.DSLContext;
import org.jooq.Records;
import org.springframework.stereotype.Service;

import java.util.List;

import static org.jooq.impl.DSL.count;

@Service
public class CustomUserRepositoryImpl implements CustomUserRepository {

    private final DSLContext dslContext;


    public CustomUserRepositoryImpl(DSLContext dslContext) {
        this.dslContext = dslContext;
    }

    @Override
    public List<UserReportResponse> reportUser() {
        return dslContext.select(
                        UserAuthority.USER_AUTHORITY.AUTHORITY_NAME,
                        count())
                .from(Users.USERS)
                .join(UserAuthority.USER_AUTHORITY)
                .on(Users.USERS.ID.eq(UserAuthority.USER_AUTHORITY.USER_ID))
                .where(Users.USERS.IS_ACTIVE.eq(true))
                .groupBy(UserAuthority.USER_AUTHORITY.AUTHORITY_NAME)
                .fetch((Records.mapping((authority, count) -> new UserReportResponse(authority, count))));

    }
}
