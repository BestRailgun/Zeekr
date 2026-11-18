package com.bestrailgun.zeeload;

import android.content.Context;
import android.os.Build;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.net.ssl.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

final class Certificates {
    private final Provider provider = new BouncyCastleProvider();
    private final PrivateKey caKey;
    private final List<X509Certificate> chain = new ArrayList<>();
    private final KeyPair leafKey;
    private final Map<String, SSLContext> cache = new LinkedHashMap<>();
    Certificates(Context context, boolean oldChain) throws Exception {
        this(context.getAssets().open("emudhra-chain.pem"), oldChain);
    }
    Certificates(InputStream pem, boolean oldChain) throws Exception {
        PrivateKey key = null;
        try (PEMParser reader = new PEMParser(new InputStreamReader(pem, java.nio.charset.StandardCharsets.US_ASCII))) {
            Object o;
            while ((o = reader.readObject()) != null) {
                if (o instanceof PrivateKeyInfo) key = new JcaPEMKeyConverter().setProvider(provider).getPrivateKey((PrivateKeyInfo)o);
                if (o instanceof X509CertificateHolder) chain.add(new JcaX509CertificateConverter().setProvider(provider).getCertificate((X509CertificateHolder)o));
            }
        }
        if (key == null || chain.isEmpty()) throw new GeneralSecurityException("内置证书链不完整");
        caKey = key;
        // Alternate issuers share the same key; do not build a discontinuous JSSE chain.
        if (oldChain) { X509Certificate last = chain.get(chain.size() - 1); chain.clear(); chain.add(last); }
        else { chain.remove(chain.size() - 1); }
        chain.get(0).checkValidity();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC"); generator.initialize(256); leafKey = generator.generateKeyPair();
    }
    synchronized SSLEngine engine(String host) throws Exception {
        SSLContext context = cache.get(host);
        if (context == null) {
            X509Certificate ca = chain.get(0);
            long now = System.currentTimeMillis();
            JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(X500Name.getInstance(ca.getSubjectX500Principal().getEncoded()),
                new BigInteger(128, new SecureRandom()).setBit(127), new Date(now - 86400000L), new Date(Math.min(now + 7 * 86400000L, ca.getNotAfter().getTime())),
                new X500Name("CN=" + host), leafKey.getPublic());
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, host)));
            String algo = caKey.getAlgorithm().equalsIgnoreCase("EC") ? "SHA256withECDSA" : "SHA256withRSA";
            X509Certificate leaf = new JcaX509CertificateConverter().setProvider(provider).getCertificate(b.build(new JcaContentSignerBuilder(algo).setProvider(provider).build(caKey)));
            leaf.verify(ca.getPublicKey());
            java.security.cert.Certificate[] certs = new java.security.cert.Certificate[chain.size() + 1]; certs[0] = leaf;
            for (int i = 0; i < chain.size(); i++) certs[i + 1] = chain.get(i);
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType()); store.load(null, null);
            char[] password = UUID.randomUUID().toString().toCharArray(); store.setKeyEntry("leaf", leafKey.getPrivate(), password, certs);
            KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); km.init(store, password);
            context = SSLContext.getInstance("TLS"); context.init(km.getKeyManagers(), null, new SecureRandom());
            if (cache.size() >= 32) cache.remove(cache.keySet().iterator().next()); cache.put(host, context);
        }
        SSLEngine e = context.createSSLEngine(); e.setUseClientMode(false); e.setNeedClientAuth(false);
        if (Build.VERSION.SDK_INT >= 29) { SSLParameters params = e.getSSLParameters(); params.setApplicationProtocols(new String[]{"http/1.1"}); e.setSSLParameters(params); }
        return e;
    }
}
