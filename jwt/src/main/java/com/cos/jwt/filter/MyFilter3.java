package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        // 토큰: cose 이녀석을 만들어 줘야함. ID, PW가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고, 그걸 응답을 해준다
        // 요청할때 마다 header에 Authorization에 value값으로 토큰을 가지고 있다.
        //  그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 한다,,! (RSA, HS256)

        //토큰 : 코스
        if (req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);
            System.out.println("필터3");
            if (headerAuth.equals("cose")) {
                chain.doFilter(req,res);
            }
            PrintWriter outPrintWriter = res.getWriter();
            outPrintWriter.println("인증안됨");
        }
    }
}