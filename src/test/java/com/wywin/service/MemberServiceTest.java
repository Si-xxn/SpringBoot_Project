package com.wywin.service;

import com.wywin.dto.MemberDTO;
import com.wywin.entity.Member;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@Transactional
public class MemberServiceTest {

    @Autowired
    MemberService memberService;

    @Autowired
    PasswordEncoder passwordEncoder;

    public Member createMember(){   // 테스트용 dto더미 생성
        /*회원 정보를 입력한 Member entity를 만드는 메서드*/
        MemberDTO memberDTO = new MemberDTO();
        memberDTO.setEmail("test@email.com");
        memberDTO.setName("홍길동");
        memberDTO.setAddress("서울시 마포구 합정동");
        memberDTO.setPhoneNum("010-1234-1234");
        memberDTO.setNickName("test00");
        memberDTO.setPassword("1234");
        return Member.createMember(memberDTO, passwordEncoder);
    }

    @Test
    public void saveMemberTest(){
        /*Junit의 Assertions 클래스의 assertEquals메서드를 이용하여 저장하려고 요청했던 값과 실제 저장된 데이터를 비교함.
        첫 번째 파라미터에는 기대 값, 두 번째 파라미터에는 실제로 저장된 값을 넣어줌 */
        Member member = createMember();
        Member savedMember = memberService.saveMember(member);

        assertEquals(member.getEmail(), savedMember.getEmail());
        assertEquals(member.getName(), savedMember.getName());
        assertEquals(member.getAddress(), savedMember.getAddress());
        assertEquals(member.getPhoneNum(), savedMember.getPhoneNum());
        assertEquals(member.getNickName(), savedMember.getNickName());
        assertEquals(member.getPassword(), savedMember.getPassword());
        assertEquals(member.getRole(), savedMember.getRole());
    }

}
