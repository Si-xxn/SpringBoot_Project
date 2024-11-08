package com.wywin.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdatePasswordDTO {

    private String email;

    private String currentPassword;

    private String newPassword;

    @Pattern(regexp = "(?=.[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%^&*]).{8,16}",
            message = "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용하세요.")
    private String newPasswordChk;
}
