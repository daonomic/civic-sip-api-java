package io.daonomic.civic.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.daonomic.civic.api.domain.*;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static java.util.Arrays.asList;

@SuppressWarnings("WeakerAccess")
public class CivicClientImpl implements CivicClient {
    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    public CivicClientImpl(String baseUrl) {
        this.webClient = WebClient.builder()
            .baseUrl(baseUrl)
            .build();
        this.objectMapper = new ObjectMapper();
    }

    public Mono<ExchangeCodeResult> exchangeCode(CivicConfig config, String token) {
        return MonoUtils.tryMono(() -> objectMapper.writeValueAsString(new AuthTokenBody(token)))
            .flatMap(requestBody -> MonoUtils.tryMono(() -> makeAuthorizationHeader(config, requestBody))
                .flatMap(header -> webClient.post()
                    .uri("/scopeRequest/authCode")
                    .body(BodyInserters.fromObject(requestBody))
                    .header("Authorization", header)
                    .retrieve()
                    .bodyToMono(AuthCodeResult.class)))
            .flatMap(result -> toExchangeCodeResult(config, result));
    }

    public Mono<ExchangeCodeResult> toExchangeCodeResult(CivicConfig config, AuthCodeResult tempResult) {
        String[] parts = tempResult.getData().split("\\.");
        if (parts.length >= 2) {
            byte[] data = Base64.decodeBase64(parts[1]);
            return MonoUtils.tryMono(() -> objectMapper.readValue(data, JsonNode.class))
                .map(node -> node.get("data").textValue())
                .flatMap(encrypted -> MonoUtils.tryMono(() -> BasicCrypto.decrypt(encrypted, config.getSecret())))
                .flatMap(decrypted -> MonoUtils.tryMono(() -> objectMapper.readValue(decrypted, UserAttribute[].class)))
                .map(attributes -> new ExchangeCodeResult(tempResult.getUserId(), asList(attributes)));
        } else {
            return Mono.error(new IllegalArgumentException("not supported data: " + tempResult.getData()));
        }
    }

    private String makeAuthorizationHeader(CivicConfig config, String requestBody) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, DecoderException {
        return "Civic " + getHeaderFirstPart(config) + "." + getHeaderSecondPart(config, requestBody);
    }

    private String getHeaderFirstPart(CivicConfig config) throws InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, DecoderException {
        Date now = new Date();
        Map<String, Object> header = new HashMap<>();
        header.put("typ", "JWT");
        header.put("alg", "ES256");

        return Jwts.builder()
            .setHeader(header)
            .setId(UUID.randomUUID().toString())
            .setIssuedAt(now)
            .setExpiration(DateUtils.addMonths(now, 3))
            .setIssuer(config.getAppId())
            .setAudience("https://api.civic.com/sip/")
            .setSubject(config.getAppId())
            .claim("data", new AuthorizationHeaderPayload("POST", "scopeRequest/authCode"))
            .signWith(SignatureAlgorithm.ES256, KeyUtils.privateKeyFromHex(config.getPrivateKey()))
            .compact();
    }

    private String getHeaderSecondPart(CivicConfig config, String requestBody) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(config.getSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKey);
        return Base64.encodeBase64String(mac.doFinal(requestBody.getBytes(StandardCharsets.UTF_8)));
    }
}
