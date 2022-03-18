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

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;
import static org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;
import de.gematik.pki.utils.P12Container;
import java.security.Security;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.xml.security.algorithms.JCEMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.XAdES4jException;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.algorithms.ExclusiveCanonicalXMLWithoutComments;
import xades4j.production.*;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;

/**
 * Class for signing tsl DOM Document structures
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class TslSigner {

    static {
        if (Security.getProvider("BC") == null) {

            Security.addProvider(new BouncyCastleProvider());
            JCEMapper.setProviderId("BC");
        }
    }

    /**
     * Signs a given tsl
     *
     * @param tsl    The tsl to sign
     * @param signer {@link P12Container} with x509certificate an key (RSA/ECC) for signature
     * @throws XAdES4jException during signature process or signer reading errors
     */
    public static void sign(final Document tsl, final P12Container signer) throws XAdES4jException {

        final Element elemToSign = getTslWithoutSignature(tsl);

        final KeyingDataProvider kdp = new DirectKeyingDataProvider(signer.getCertificate(), signer.getPrivateKey());

        final XadesSigner xSigner = new XadesBesSigningProfile(kdp)
            .withSignatureAlgorithms(new SignatureAlgorithms()
                .withSignatureAlgorithm("RSA", ALGO_ID_SIGNATURE_RSA_SHA256_MGF1)
                .withCanonicalizationAlgorithmForSignature(new ExclusiveCanonicalXMLWithoutComments())
                .withCanonicalizationAlgorithmForTimeStampProperties(new ExclusiveCanonicalXMLWithoutComments())
            )
            .withBasicSignatureOptions(new BasicSignatureOptions().includeIssuerSerial(false).includeSubjectName(false))
            .newSigner();
        final DataObjectDesc dod = new DataObjectReference("")
            .withTransform(new EnvelopedSignatureTransform())
            .withTransform(new ExclusiveCanonicalXMLWithoutComments())
            .withDataObjectFormat(new DataObjectFormatProperty("text/xml", ""));

        xSigner.sign(new SignedDataObjects(dod), elemToSign);
    }

    private static Element getTslWithoutSignature(final Document tsl) {
        final Element signature = (Element) tsl.getElementsByTagNameNS(XMLNS, "Signature").item(0);
        if (signature != null) {
            final Element elemToSign = (Element) signature.getParentNode();
            elemToSign.removeChild(signature);
            return elemToSign;
        } else {
            return tsl.getDocumentElement();
        }
    }
}
