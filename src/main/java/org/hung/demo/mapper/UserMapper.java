package org.hung.demo.mapper;

import org.hung.demo.domain.User;
import org.hung.demo.dto.request.CreateUserRequest;
import org.hung.demo.dto.response.UserDetailResponse;
import org.hung.demo.dto.response.UserListResponse;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface UserMapper {

    UserMapper INSTANCE = Mappers.getMapper( UserMapper.class );

    UserListResponse userToUserListResponse(User user);


    UserDetailResponse userToUserDetail(User user);

    User createUserRequestToUser(CreateUserRequest createUserRequest);
}
