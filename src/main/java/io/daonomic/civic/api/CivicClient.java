package io.daonomic.civic.api;

import io.daonomic.civic.api.domain.ExchangeCodeResult;
import reactor.core.publisher.Mono;

public interface CivicClient {
    Mono<ExchangeCodeResult> exchangeCode(String token);
}
