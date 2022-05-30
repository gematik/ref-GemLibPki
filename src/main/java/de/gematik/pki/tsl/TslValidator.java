/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.tsl;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.XAdES4jException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

/**
 * Class to validate a TSL by checking its signature
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class TslValidator {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            JCEMapper.setProviderId(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    /**
     * Check signature of given TSL (mathematically and against trust anchor).
     *
     * @param tsl         the tsl to check
     * @param trustAnchor the tsl trust anchor certificate (issuer of signing certificate)
     * @return true if signature is valid, otherwise false
     * @throws IOException if files cannot be read
     */
    public static boolean checkSignature(@NonNull final Document tsl, @NonNull final X509Certificate trustAnchor) throws IOException {

        try {
            final Optional<XAdESVerificationResult> xvr = getVerificationResult(tsl, trustAnchor);
            if (xvr.isEmpty()) {
                return false;
            }
            return xvr.get().getXmlSignature().checkSignatureValue(xvr.get().getValidationCertificate());
        } catch (final XAdES4jException | NoSuchAlgorithmException | XMLSignatureException | NoSuchProviderException | CertificateException |
                       KeyStoreException e) {
            return false;
        }
    }

    private static Optional<XAdESVerificationResult> getVerificationResult(final Document tsl, final X509Certificate trustAnchor)
        throws XAdES4jException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException {

        final KeyStore trustAnchorStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustAnchorStore.load(null);
        trustAnchorStore.setCertificateEntry(trustAnchor.getSubjectX500Principal().getName(), trustAnchor);

        final CertificateValidationProvider certValidator = PKIXCertificateValidationProvider.builder(trustAnchorStore)
            .certPathBuilderProvider(BouncyCastleProvider.PROVIDER_NAME)
            .checkRevocation(false)
            .build();

        final XadesVerificationProfile p = new XadesVerificationProfile(certValidator);
        final XadesVerifier v = p.newVerifier();

        final Element sigElem = (Element) tsl.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature").item(0);
        if (sigElem == null) {
            return Optional.empty();
        }
        return Optional.of(v.verify(sigElem, null));
    }
}
