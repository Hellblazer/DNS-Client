package org.xbill.DNS;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

import junit.framework.TestCase;

import org.xbill.DNS.DNSSEC.Algorithm;

public class DNSSECWithProviderTest extends TestCase {

    private static final String KEY_ALGORITHM       = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
    int                         algorithm           = Algorithm.RSASHA1;
    byte[]                      toSign              = "The quick brown fox jumped over the lazy dog.".getBytes();

    @Override
    public void setUp() {
    }

    @Override
    public void tearDown() {
    }

    public void testSignSoftware() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.initSign(keyPair.getPrivate());
        signer.update(toSign);
        byte[] signature = signer.sign();
        assertNotNull(signature);

        // verify the signature
        Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(toSign);
        boolean verify = verifier.verify(signature);
        assertTrue(verify);

    }
}
