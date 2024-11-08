package com.wywin.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MemberUpdateDTO {

    private String email;

    @NotEmpty(message = "전화번호는 필수 입력 값입니다.")
    private String phoneNum;

    @NotEmpty(message = "주소는 필수 입력 값입니다.")
    private String address;

    @NotEmpty(message = "닉네임은 필수 입력 값입니다.")
    private String nickName;
}
