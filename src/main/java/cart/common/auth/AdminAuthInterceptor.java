package cart.common.auth;

import cart.domain.MemberPassword;
import cart.domain.MemberRole;
import cart.exception.ErrorCode;
import cart.exception.ForbiddenException;
import cart.exception.GlobalException;
import cart.service.MemberService;
import cart.service.dto.MemberResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class AdminAuthInterceptor implements HandlerInterceptor {

    private static final String DELIMITER = ":";
    private static final String AUTHORIZATION_HEADER = "Authorization";

    private final MemberService memberService;

    public AdminAuthInterceptor(MemberService memberService) {
        this.memberService = memberService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) {
        final String authorization = request.getHeader(AUTHORIZATION_HEADER);
        final String memberToken = BasicTokenProvider.extractToken(authorization);
        final String memberEmail = memberToken.split(DELIMITER)[0];
        final String memberPassword = memberToken.split(DELIMITER)[1];
        final MemberResponse memberResponse = memberService.getByEmail(memberEmail);
        validatePassword(memberPassword, memberResponse.getPassword());
        validateAdminUser(memberResponse.getRole());
        return true;
    }

    private void validatePassword(final String requestPassword, final String savedPassword) {
        final String decodedPassword = MemberPassword.decodePassword(requestPassword);
        if (!savedPassword.equals(decodedPassword)) {
            throw new GlobalException(ErrorCode.MEMBER_PASSWORD_INVALID);
        }
    }

    private void validateAdminUser(final String role) {
        boolean isAdmin = MemberRole.isAdmin(role);
        if (!isAdmin) {
            throw new ForbiddenException();
        }
    }
}
