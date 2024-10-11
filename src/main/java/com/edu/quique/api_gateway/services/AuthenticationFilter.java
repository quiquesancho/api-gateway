package com.edu.quique.api_gateway.services;

import com.edu.quique.api_gateway.utils.JwtUtils;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


import static com.edu.quique.api_gateway.utils.AppConstants.HEADER_AUTHORIZATION_KEY;
import static com.edu.quique.api_gateway.utils.AppConstants.TOKEN_BEARER_PREFIX;

@Component
public class AuthenticationFilter
    extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

  private final RouterValidator routerValidator;
  private final JwtUtils jwtUtils;

  public AuthenticationFilter(RouterValidator routerValidator, JwtUtils jwtUtils) {
    super(Config.class);
    this.routerValidator = routerValidator;
    this.jwtUtils = jwtUtils;
  }

  @Override
  public GatewayFilter apply(Config config) {
    return ((exchange, chain) -> {
      ServerHttpRequest req = exchange.getRequest();
      String path = req.getURI().getPath();

      ServerHttpRequest serverHttpRequest = null;

      if (routerValidator.isSecured.test(req)) {
        if (authMissing(req)) {
          return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        String authHeader = exchange.getRequest().getHeaders().get(HEADER_AUTHORIZATION_KEY).get(0);

        if (authHeader != null && authHeader.startsWith(TOKEN_BEARER_PREFIX)) {
          authHeader = authHeader.replace(TOKEN_BEARER_PREFIX, "");
        } else {
          return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        if (jwtUtils.isExpired(authHeader)) {
          return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        serverHttpRequest =
            exchange
                .getRequest()
                .mutate()
                .header("userIdRequest", jwtUtils.extractSubject(authHeader))
                .build();
      }
      return chain.filter(exchange.mutate().request(serverHttpRequest).build());
    });
  }

  private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
      ServerHttpResponse res = exchange.getResponse();
      res.setStatusCode(status);
      return null;
  }

  private boolean authMissing(ServerHttpRequest req) {
      return !req.getHeaders().containsKey(HEADER_AUTHORIZATION_KEY);
  }

  public static class Config {}
}
