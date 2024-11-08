package com.wywin.controller;

import com.wywin.dto.MemberDTO;
import com.wywin.dto.MemberUpdateDTO;
import com.wywin.dto.UpdatePasswordDTO;
import com.wywin.entity.Member;
import com.wywin.repository.MemberRepository;
import com.wywin.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;


import java.security.Principal;

@Log4j2
@Controller
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberController {

    private final MemberService memberService;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;


    @GetMapping(value = "/new")
    public String memberForm(Model model){/* 회원 가입 페이지로 이동할 수 있도록 MemberController클래스에 메소드를 작성*/
        model.addAttribute("memberDTO", new MemberDTO());
        return "member/sign_up";
    }

    @PostMapping(value = "/new") // 회원 가입 POST 메서드
    public String newMember(@Valid MemberDTO memberDTO, BindingResult bindingResult, Model model){
        // spring-boot-starter-validation를 활용한 검증 bindingResult객체 추가
        if(bindingResult.hasErrors()){
            /*검증하려는 객체의 앞에 @Valid 어노테이션을 선언하고, 파라미터로 bindingResult 객체를 추가함.
        검사 결과는 bindingResult에 담아줌. bindingResult.hasErrors()를 호출하여 에러가 있다면 회원가입 페이지로 이동함*/
            return "member/sign_up";
            // 검증 후 결과를 bindingResult에 담아 준다.
        }

        try {
            Member member = Member.createMember(memberDTO, passwordEncoder);
            memberService.saveMember(member);
            // 가입 처리시 이메일이 중복이면 메시지를 전달한다.
        } catch (IllegalStateException e){
            model.addAttribute("errorMessage", e.getMessage());
            /*회원가입시 중복 회원 가입 예외 발생시 에러 메시지를 뷰로 전달함*/
            return "member/sign_up";
        }

        return "redirect:/";
    }

    @GetMapping(value = "/login") // 로그인 페이지 가져옴
    public String loginMember() {
        return "member/login";
    }

    @GetMapping(value = "/login/error") // 로그인 오류시 처리
    public String loginError(Model model) {
        model.addAttribute("loginErrorMsg", "아이디 또는 비밀번호를 확인해주세요");
        return "member/login";
    }

    @GetMapping(value = "/myPage") // 마이페이지 가져옴
    public String myPage(Principal principal, Model model) {
        String memberInfo = principal.getName();
        Member member = memberRepository.findByEmail(memberInfo);
        model.addAttribute("member", member);

        return "member/profile";
    }

    @GetMapping(value = "/update") // 정보수정 페이지
    public String updateForm(Principal principal, Model model) {
        String memberInfo = principal.getName();
        Member member = memberRepository.findByEmail(memberInfo);
        model.addAttribute("member", member);

        return "member/updateForm";
    }

    @PostMapping(value = "/update") // 정보수정 처리
    public String updateMember(@Valid MemberUpdateDTO memberUpdateDTO, Model model) {
        model.addAttribute("member", memberUpdateDTO);
        memberService.updateMember(memberUpdateDTO);

        return "redirect:/members/myPage";
    }

    @GetMapping("/changePassword")
    public String showChangePasswordPage(Model model) {
        model.addAttribute("updatePasswordDTO", new UpdatePasswordDTO());
        return "member/changePassword";
    }
/*
    @ResponseBody
    @PostMapping("/change-password") // 비밀번호 변경 메서드
    public String changePassword(@RequestBody UpdatePasswordDTO updatePasswordDTO) {
        // 서비스에서 비밀번호 변경 수행
        return memberService.changePassword(updatePasswordDTO);
    }

    @PostMapping("/check-current-password")
    public boolean checkCurrentPassword(@RequestBody UpdatePasswordDTO updatePasswordDTO) {
        return memberService.checkCurrentPassword(updatePasswordDTO.getEmail(), updatePasswordDTO.getCurrentPassword());
    }
*/

}
