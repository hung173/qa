package org.hung.demo.repository.custom;

import org.hung.demo.dto.response.UserReportResponse;

import java.util.List;

public interface CustomUserRepository {

    List<UserReportResponse> reportUser();

}
