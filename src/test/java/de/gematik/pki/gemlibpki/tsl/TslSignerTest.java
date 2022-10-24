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

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_RSA_ALT_TA;
import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_RSA_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_RSA_NOSIG;
import static de.gematik.pki.gemlibpki.utils.TestUtils.readP12;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.GemlibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.ResourceReader;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import xades4j.XAdES4jXMLSigException;

class TslSignerTest {

  private static final String SIGNER_PATH_RSA = "GEM.TSL-CA40/TSL-Signer40.p12";

  private static final String SIGNER_PATH_ECC = "GEM.TSL-CA8/TSL-Signing-Unit-8-TEST-ONLY.p12";

  private static Document tslRsa, tslRsaNoSig, tslEcc;
  private static final X509Certificate trustAnchorRsa =
      TestUtils.readCert("GEM.TSL-CA40/GEM.TSL-CA40-TEST-ONLY.pem");
  private static final X509Certificate trustAnchorEcc =
      TestUtils.readCert("GEM.TSL-CA8/GEM.TSL-CA8_brainpoolIP256r1.der");

  @BeforeAll
  public static void setup() {
    tslRsa =
        TslReader.getTslAsDoc(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_RSA_DEFAULT))
            .orElseThrow();

    final P12Container signerRsa = readP12(SIGNER_PATH_RSA);
    TslSigner.sign(tslRsa, signerRsa);
    tslRsaNoSig =
        TslReader.getTslAsDoc(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_RSA_NOSIG))
            .orElseThrow();
    TslSigner.sign(tslRsaNoSig, signerRsa);
    tslEcc =
        TslReader.getTslAsDoc(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT))
            .orElseThrow();

    final P12Container signerEcc = readP12(SIGNER_PATH_ECC);
    TslSigner.sign(tslEcc, signerEcc);
  }

  @Test
  void bouncyCastleProviderIsSetRsa() {
    // now remove the BouncyCastleProvider
    final Document tslRsa =
        TslReader.getTslAsDoc(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_RSA_DEFAULT))
            .orElseThrow();
    final P12Container signerRsa = readP12(SIGNER_PATH_RSA);

    assertDoesNotThrow(() -> TslSigner.sign(tslRsa, signerRsa));
    // now remove the BouncyCastleProvider
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);

    assertThatThrownBy(() -> TslSigner.sign(tslRsa, signerRsa))
        .isInstanceOf(GemPkiRuntimeException.class)
        .cause()
        .isInstanceOf(XAdES4jXMLSigException.class)
        .hasMessage(
            "The requested algorithm http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1 does"
                + " not exist. Original Message was:"
                + " org.apache.xml.security.algorithms.implementations.SignatureBaseRSA$SignatureRSASHA256MGF1");
    // ... and then restore the BouncyCastleProvider
    GemlibPkiUtils.setBouncyCastleProvider();
  }

  @Test
  void bouncyCastleProviderIsSetEcc() {
    // now remove the BouncyCastleProvider
    final Document tslEcc =
        TslReader.getTslAsDoc(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT))
            .orElseThrow();
    final P12Container signerEcc = readP12(SIGNER_PATH_ECC);

    assertDoesNotThrow(() -> TslSigner.sign(tslEcc, signerEcc));
    // now remove the BouncyCastleProvider
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);

    assertThatThrownBy(() -> TslSigner.sign(tslEcc, signerEcc))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Fehler bei erstellen der XAdES Signatur.")
        .cause()
        .isInstanceOf(XAdES4jXMLSigException.class)
        .hasMessageStartingWith("Curve not supported: org.bouncycastle.jce.spec.ECNamedCurveSpec@");
    // ... and then restore the BouncyCastleProvider
    GemlibPkiUtils.setBouncyCastleProvider();
  }

  @Test
  void verifySignatureRsaValid() {
    assertThat(TslValidator.checkSignature(tslRsa, trustAnchorRsa)).isTrue();
  }

  @Test
  void verifySignatureRsaNoSigValid() {
    assertThat(TslValidator.checkSignature(tslRsaNoSig, trustAnchorRsa)).isTrue();
  }

  @Test
  void verifySignatureEccValid() {
    assertThat(TslValidator.checkSignature(tslEcc, trustAnchorEcc)).isTrue();
  }

  @Test
  void verifySignatureRsaInvalid() {
    final NodeList tslSeqNrElem = tslRsa.getElementsByTagName("TSLSequenceNumber");
    assertThat(tslSeqNrElem.getLength()).isPositive();
    // destroy signature by modifying text in tsl
    tslSeqNrElem.item(0).setTextContent("notAValidNumber");
    assertThat(TslValidator.checkSignature(tslRsa, trustAnchorRsa)).isFalse();
  }

  @Test
  void verifySignatureWrongTa() {
    final Document tslAltTa =
        TslReader.getTslAsDoc(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_RSA_ALT_TA))
            .orElseThrow();
    assertThat(TslValidator.checkSignature(tslAltTa, trustAnchorRsa)).isFalse();
  }

  @Test
  void verifySignatureMissing() {
    final Element signature = TslUtils.getSignature(tslRsa);
    final Element tsl_new = (Element) signature.getParentNode();
    tsl_new.removeChild(signature);
    assertThat(TslValidator.checkSignature(tsl_new.getOwnerDocument(), trustAnchorRsa)).isFalse();
  }

  @Test
  void nonNull() {
    final P12Container container = readP12(SIGNER_PATH_RSA);
    assertThatThrownBy(() -> TslSigner.sign(null, container))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    assertThatThrownBy(() -> TslSigner.sign(tslEcc, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tslSigner is marked non-null but is null");
  }
}
