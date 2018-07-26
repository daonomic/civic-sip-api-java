package io.daonomic.civic.api;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.spec.*;

public class KeyUtils {
    //todo impl
    public static final String CIVIC_PUB = "049a45998638cfb3c4b211d72030d9ae8329a242db63bfb0076a54e7647370a8ac5708b57af6065805d5a6be72332620932dbb35e8d318fce18e7c980a0eb26aa1";

    public static PrivateKey privateKeyFromHex(String hex) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, DecoderException, InvalidKeySpecException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        AlgorithmParameterSpec prime256v1ParamSpec = new ECGenParameterSpec("secp256r1");

        keyPairGenerator.initialize(prime256v1ParamSpec);

        ECParameterSpec parameterSpec = ((ECKey)keyPairGenerator.generateKeyPair().getPrivate()).getParams();

        BigInteger privateKeyInt = new BigInteger(1, Hex.decodeHex(hex));

        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyInt, parameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(privateKeySpec);
    }
}
