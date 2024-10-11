package com.edu.quique.api_gateway.services;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Predicate;

@Service
public class RouterValidator {
  public static final List<String> openRoutes = List.of("/auth/login");

  public Predicate<ServerHttpRequest> isSecured =
      serverHttpRequest ->
          openRoutes.stream().noneMatch(uri -> serverHttpRequest.getURI().getPath().contains(uri));
}
