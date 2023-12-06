package org.hung.demo.mapper;

import org.hung.demo.domain.Authority;
import org.hung.demo.domain.User;
import org.hung.demo.dto.request.CreateUserRequest;
import org.hung.demo.dto.response.UserDetailResponse;
import org.hung.demo.dto.response.UserListResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;
import org.mapstruct.factory.Mappers;

import java.util.List;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserMapper INSTANCE = Mappers.getMapper( UserMapper.class );

    UserListResponse userToUserListResponse(User user);

    @Mappings({
            @Mapping(target = "authorities", source = "authorities")
    })
    UserDetailResponse userToUserDetail(User user);

    @Mapping(target = "authorities", ignore = true)
    User createUserRequestToUser(CreateUserRequest createUserRequest);

    default String mapAuthorityString(Authority authority) {
        return authority.getName();
    }
}
