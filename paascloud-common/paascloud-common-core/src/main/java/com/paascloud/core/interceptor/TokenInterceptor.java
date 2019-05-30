package com.paascloud.core.interceptor;

import com.paascloud.RedisKeyUtil;
import com.paascloud.ThreadLocalMap;
import com.paascloud.annotation.NoNeedAccessAuthentication;
import com.paascloud.base.constant.GlobalConstant;
import com.paascloud.base.dto.LoginAuthDto;
import com.paascloud.base.dto.UserTokenDto;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Method;

/**
 * The class Token interceptor.
 *
 * @author paascloud.net @gmail.com
 */
@Slf4j
public class TokenInterceptor implements HandlerInterceptor {

	@Value("${paascloud.oauth2.jwtSigningKey}")
	private String jwtSigningKey;

	@Resource
	private RedisTemplate<String, Object> redisTemplate;

	private static final String OPTIONS = "OPTIONS";
	private static final String AUTH_PATH1 = "/auth";
	private static final String AUTH_PATH2 = "/oauth";
	private static final String AUTH_PATH3 = "/error";
	private static final String AUTH_PATH4 = "/api";

	/**
	 * After completion.
	 *
	 * @param request  the request
	 * @param response the response
	 * @param arg2     the arg 2
	 * @param ex       the ex
	 *
	 * @throws Exception the exception
	 */
	@Override
	public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object arg2, Exception ex) throws Exception {
		if (ex != null) {
			log.error("<== afterCompletion - 解析token失败. ex={}", ex.getMessage(), ex);
			this.handleException(response);
		}
	}

	/**
	 * Post handle.
	 *
	 * @param request  the request
	 * @param response the response
	 * @param arg2     the arg 2
	 * @param mv       the mv
	 */
	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, Object arg2, ModelAndView mv) {
	}

	/**
	 * Pre handle boolean.
	 *
	 * @param request  the request
	 * @param response the response
	 * @param handler  the handler
	 *
	 * @return the boolean
	 */
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
		String uri = request.getRequestURI();
		log.info("<== preHandle - 权限拦截器.  url={}", uri);
		if (uri.contains(AUTH_PATH1) || uri.contains(AUTH_PATH2) || uri.contains(AUTH_PATH3) || uri.contains(AUTH_PATH4)) {
			log.info("<== preHandle - 配置URL不走认证.  url={}", uri);
			return true;
		}
		log.info("<== preHandle - 调试模式不走认证.  OPTIONS={}", request.getMethod().toUpperCase());

		if (OPTIONS.equalsIgnoreCase(request.getMethod())) {
			log.info("<== preHandle - 调试模式不走认证.  url={}", uri);
			return true;
		}

		if (isHaveAccess(handler)) {
			log.info("<== preHandle - 不需要认证注解不走认证.  token={}");
			return true;
		}

		String token = StringUtils.substringAfter(request.getHeader(HttpHeaders.AUTHORIZATION), "Bearer ");
//		String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJhZG1pbiIsInNjb3BlIjpbIioiXSwibG9naW5OYW1lIjoiYWRtaW4iLCJleHAiOjE1NTkyMDc0MDEsImF1dGhvcml0aWVzIjpbIi9jYXJ0L2RlbGV0ZVByb2R1Y3QvKiIsIi9tZW51L3NhdmUiLCIvcm9sZS9iaW5kQWN0aW9uIiwiL2FjdGlvbi9kZWxldGVBY3Rpb25CeUlkLyoiLCIvbWVudS9tb2RpZnlTdGF0dXMiLCIvb21jL3Byb2R1Y3QvZGVsZXRlUHJvZHVjdEJ5SWQvKiIsIi9yb2xlL2RlbGV0ZVJvbGVCeUlkLyoiLCIvb21jL2NhdGVnb3J5L2RlbGV0ZUJ5SWQvKiIsIi9kaWN0L21vZGlmeVN0YXR1cyIsIi9vcmRlci9jcmVhdGVPcmRlckRvYy8qIiwiL2VtYWlsL3NlbmRSZXN0RW1haWxDb2RlIiwiL21lbnUvZGVsZXRlQnlJZC8qIiwiL2dyb3VwL2RlbGV0ZUJ5SWQvKiIsIi91c2VyL2JpbmRSb2xlIiwiL3NoaXBwaW5nL3NldERlZmF1bHRBZGRyZXNzLyoiLCIvYWN0aW9uL21vZGlmeVN0YXR1cyIsIi9ncm91cC9zYXZlIiwiL2dyb3VwL2JpbmRVc2VyIiwiL2RpY3Qvc2F2ZSIsIi9hY3Rpb24vY2hlY2tVcmwiLCIvYWN0aW9uL2JhdGNoRGVsZXRlQnlJZExpc3QiLCIvY2FydC9zZWxlY3RBbGxQcm9kdWN0IiwiL2FjdGlvbi9jaGVja0FjdGlvbkNvZGUiLCIvb3JkZXIvY2FuY2VsT3JkZXJEb2MvKiIsIi9yb2xlL21vZGlmeVJvbGVTdGF0dXNCeUlkIiwiL3NoaXBwaW5nL2RlbGV0ZVNoaXBwaW5nLyoiLCIvY2FydC91blNlbGVjdFByb2R1Y3QvKiIsIi9zaGlwcGluZy91cGRhdGVTaGlwcGluZy8qIiwiL2dyb3VwL21vZGlmeVN0YXR1cyIsIi9yb2xlL2JpbmRVc2VyIiwiL3VhYy9yb2xlL3F1ZXJ5TGlzdCIsIi9vbWMvcHJvZHVjdC9zYXZlIiwiL3BheS9hbGlwYXlDYWxsYmFjayIsIi9vbWMvY2F0ZWdvcnkvbW9kaWZ5U3RhdHVzIiwiL2NhcnQvdXBkYXRlSW5mb3JtYXRpb24iLCIvY2FydC91blNlbGVjdEFsbFByb2R1Y3QiLCIvZGljdC9kZWxldGVCeUlkLyoiLCIvdXNlci9zYXZlIiwiL2NhcnQvdXBkYXRlUHJvZHVjdC8qKiIsIi91c2VyL3Jlc2V0TG9naW5Qd2QiLCIvcGF5L2NyZWF0ZVFyQ29kZUltYWdlLyoiLCIvYWN0aW9uL3F1ZXJ5TGlzdFdpdGhQYWdlIiwiL2NhcnQvc2VsZWN0UHJvZHVjdC8qIiwiL2NhcnQvYWRkUHJvZHVjdC8qKiIsIi9yb2xlL3NhdmUiLCIvYWN0aW9uL3NhdmUiLCIvdXNlci9tb2RpZnlVc2VyU3RhdHVzQnlJZCIsIi9zaGlwcGluZy9hZGRTaGlwcGluZyIsIi9vbWMvY2F0ZWdvcnkvc2F2ZSIsIi9yb2xlL2JpbmRNZW51IiwiL3JvbGUvYmF0Y2hEZWxldGVCeUlkTGlzdCJdLCJqdGkiOiJkYjhkM2MzMi03NjdhLTQ3NzktOWZlOC0yOTY2NjkxZmMwZjUiLCJjbGllbnRfaWQiOiJwYWFzY2xvdWQtY2xpZW50LXVhYyIsInRpbWVzdGFtcCI6MTU1OTIwMDIwMTAyN30.-SNN6heFpT8qnDt9GVPKL7oo_8YZyouVvPy3wCjqkJw";
		log.info("<== preHandle - 权限拦截器.  token={}", token);
		LoginAuthDto loginUser = (UserTokenDto) redisTemplate.opsForValue().get(RedisKeyUtil.getAccessTokenKey(token));
		if (loginUser == null) {
			log.error("获取用户信息失败, 不允许操作");
			return false;
		}
		log.info("<== preHandle - 权限拦截器.  loginUser={}", loginUser);
		ThreadLocalMap.put(GlobalConstant.Sys.TOKEN_AUTH_DTO, loginUser);
		log.info("<== preHandle - 权限拦截器.  url={}, loginUser={}", uri, loginUser);
		return true;
	}

	private void handleException(HttpServletResponse res) throws IOException {
		res.resetBuffer();
		res.setHeader("Access-Control-Allow-Origin", "*");
		res.setHeader("Access-Control-Allow-Credentials", "true");
		res.setContentType("application/json");
		res.setCharacterEncoding("UTF-8");
		res.getWriter().write("{\"code\":100009 ,\"message\" :\"解析token失败\"}");
		res.flushBuffer();
	}

	private boolean isHaveAccess(Object handler) {
		HandlerMethod handlerMethod = (HandlerMethod) handler;
		Method method = handlerMethod.getMethod();
		NoNeedAccessAuthentication responseBody = AnnotationUtils.findAnnotation(method, NoNeedAccessAuthentication.class);
		return responseBody != null;
	}

}
  