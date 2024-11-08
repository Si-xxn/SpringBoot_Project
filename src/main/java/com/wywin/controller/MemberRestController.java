package com.wywin.controller;

import com.wywin.dto.UpdatePasswordDTO;
import com.wywin.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class MemberRestController {

    private final MemberService memberService;


    // 현재 비밀번호 확인 API
    @PostMapping(value = "/changePassword")
    public ResponseEntity<?> changePassword(@Valid @RequestBody UpdatePasswordDTO updatePasswordDTO) {
        // 새 비밀번호와 새 비밀번호 확인 일치 여부 확인
        if(!updatePasswordDTO.getNewPassword().equals(updatePasswordDTO.getNewPasswordChk())) {
            return ResponseEntity.badRequest().body("새 비밀번호와 비밀번호 확인이 일치하지 않습니다.");
        }

        // 현재 비밀번호가 맞는지 확인
        int isVerified = memberService.verifyCurrentPassword(updatePasswordDTO.getEmail(), updatePasswordDTO.getCurrentPassword());
        if(isVerified == 0) {
            return ResponseEntity.status(403).body("현재 비밀번호가 일치하지 않습니다.");
        }

        // 비밀번호 변경 수행
        int isChanged = memberService.changePassword(updatePasswordDTO.getEmail(), updatePasswordDTO.getNewPassword());
        if(isChanged == 1) {
            return ResponseEntity.ok().body("비밀번호가 성공적으로 변경되었습니다.");
        } else {
            return ResponseEntity.status(400).body("비밀번호 변경에 실패했습니다.");
        }
    }

}