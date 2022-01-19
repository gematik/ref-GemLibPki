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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import de.gematik.pki.utils.CertReader;
import de.gematik.pki.utils.P12Container;
import de.gematik.pki.utils.P12Reader;
import de.gematik.pki.utils.ResourceReader;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.Objects;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.UnsupportedAlgorithmException;

class TslSignerTest {

    private static final String TSL_PATH_RSA = "tsls/valid/TSL-test.xml";
    private static final String TSL_PATH_RSA_NOSIG = "tsls/valid/TSL-test_nosig.xml";
    private static final String TRUSTANCHOR_PATH_RSA = "certificates/GEM.TSL-CA4/GEM.TSL-CA4_TEST-ONLY.cer";
    private static final String SIGNER_PATH_RSA = "certificates/GEM.TSL-CA4/tslSigner.p12";
    private static final String TSL_PATH_ECC = "tsls/valid/ECC-RSA_TSL-test.xml";
    private static final String TRUSTANCHOR_PATH_ECC = "certificates/GEM.TSL-CA8/GEM.TSL-CA8_brainpoolIP256r1.der";
    private static final String SIGNER_PATH_ECC = "certificates/GEM.TSL-CA8/TSL-Signing-Unit-8-TEST-ONLY.p12";

    private static Document tslRsa, tslRsaNoSig, tslEcc;
    private static X509Certificate trustAnchorRsa, trustAnchorEcc;


    @SneakyThrows
    @BeforeAll
    public static void setup() {

        tslRsa = TslReader.getTslAsDoc(ResourceReader.getFilePathFromResources(TSL_PATH_RSA)).orElseThrow();
        trustAnchorRsa = CertReader
            .readX509(Files.readAllBytes(ResourceReader.getFilePathFromResources(TRUSTANCHOR_PATH_RSA)));
        final P12Container signerRsa = readSignerCert(SIGNER_PATH_RSA);
        TslSigner.sign(tslRsa, signerRsa);

        tslRsaNoSig = TslReader.getTslAsDoc(ResourceReader.getFilePathFromResources(TSL_PATH_RSA_NOSIG)).orElseThrow();
        TslSigner.sign(tslRsaNoSig, signerRsa);

        tslEcc = TslReader.getTslAsDoc(ResourceReader.getFilePathFromResources(TSL_PATH_ECC)).orElseThrow();
        trustAnchorEcc = CertReader
            .readX509(Files.readAllBytes(ResourceReader.getFilePathFromResources(TRUSTANCHOR_PATH_ECC)));
        final P12Container signerEcc = readSignerCert(SIGNER_PATH_ECC);
        TslSigner.sign(tslEcc, signerEcc);
    }

    @SneakyThrows
    @Test
    void verifySignatureRsaValid() {
        assertThat(TslValidator.checkSignature(tslRsa, trustAnchorRsa)).isTrue();
    }

    @SneakyThrows
    @Test
    void verifySignatureRsaNoSigValid() {
        assertThat(TslValidator.checkSignature(tslRsaNoSig, trustAnchorRsa)).isTrue();
    }

    @SneakyThrows
    @Test
    void verifySignatureEccValid() {
        assertThat(TslValidator.checkSignature(tslEcc, trustAnchorEcc)).isTrue();
    }

    @SneakyThrows
    @Test
    void verifySignatureRsaInvalid() {
        //destroy signature by modifying text in tsl
        tslRsa.getElementsByTagName("TSLSequenceNumber").item(0).setTextContent("666");
        assertThat(TslValidator.checkSignature(tslRsa, trustAnchorRsa)).isFalse();
    }

    @SneakyThrows
    @Test
    void verifySignatureWrongTa() {
        final String FILE_NAME_TSL_DEFAULT_ALT_TA = "tsls/valid/TSL-test.xml";
        final Document tslAltTa = TslReader.getTslAsDoc(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT_ALT_TA)).orElseThrow();
        assertThat(TslValidator.checkSignature(tslAltTa, trustAnchorRsa)).isFalse();
    }

    @SneakyThrows
    @Test
    void verifySignatureMissing() {
        final Element signature = (Element) tslRsa.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature").item(0);
        final Element tsl_new = (Element) signature.getParentNode();
        tsl_new.removeChild(signature);

        assertThat(TslValidator.checkSignature(tsl_new.getOwnerDocument(), trustAnchorRsa))
            .isFalse();
    }

    @SneakyThrows
    @Test
    void signDsaNotSupported() {
        final String SIGNER_PATH_DSA = "certificates/ocsp/dsaCert.p12";
        assertThatThrownBy(() -> TslSigner.sign(tslEcc, readSignerCert(SIGNER_PATH_DSA)))
            .hasMessage("Signature algorithm not supported by the provider (DSA)")
            .isInstanceOf(UnsupportedAlgorithmException.class);
    }

    @SneakyThrows
    private static P12Container readSignerCert(final String certPath) {
        return Objects.requireNonNull(P12Reader.getContentFromP12(ResourceReader.getFilePathFromResources(certPath), "00"));
    }

}
