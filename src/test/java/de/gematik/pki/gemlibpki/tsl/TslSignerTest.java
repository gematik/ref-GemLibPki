/*
 * Copyright (c) 2023 gematik GmbH
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

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_RSA_ALT_TA;
import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_RSA_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_RSA_NOSIG;
import static de.gematik.pki.gemlibpki.tsl.TslConverter.docToBytes;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static de.gematik.pki.gemlibpki.utils.TestUtils.readP12;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TslSigner.TslSignerBuilder;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import xades4j.XAdES4jXMLSigException;
import xades4j.production.SigningCertKeyUsageException;
import xades4j.production.SigningCertValidityException;

class TslSignerTest {

  private static final String SIGNER_PATH_RSA = "GEM.TSL-CA40/TSL-Signer40.p12";

  public static final String SIGNER_PATH_ECC = "GEM.TSL-CA8/TSL-Signing-Unit-8-TEST-ONLY.p12";

  private static Document tslRsa;
  private static Document tslRsaNoSig;
  private static Document tslEcc;

  private static final X509Certificate trustAnchorRsa =
      TestUtils.readCert("GEM.TSL-CA40/GEM.TSL-CA40-TEST-ONLY.pem");
  private final TslSignerBuilder tslSignerBuilder = TslSigner.builder();

  @BeforeEach
  public void setup() {
    tslRsa = TestUtils.getTslAsDoc(FILE_NAME_TSL_RSA_DEFAULT);

    final P12Container signerRsa = readP12(SIGNER_PATH_RSA);

    tslSignerBuilder.tslToSign(tslRsa).tslSignerP12(signerRsa).build().sign();
    tslRsaNoSig = TestUtils.getTslAsDoc(FILE_NAME_TSL_RSA_NOSIG);

    tslSignerBuilder.tslToSign(tslRsaNoSig).tslSignerP12(signerRsa).build().sign();
    tslEcc = TestUtils.getDefaultTslAsDoc();

    final P12Container signerEcc = readP12(SIGNER_PATH_ECC);
    tslSignerBuilder.tslToSign(tslEcc).tslSignerP12(signerEcc).build().sign();
  }

  public static final X509Certificate TRUST_ANCHOR_ECC =
      TestUtils.readCert("GEM.TSL-CA8/GEM.TSL-CA8_brainpoolIP256r1.der");

  @Test
  void verifyCheckKeyUsageDisabled() {
    final Document tslEcc = TestUtils.getDefaultTslAsDoc();
    final P12Container invalidKeyUsageSigner =
        readP12("GEM.TSL-CA8/TSL-Signing-Unit-8_invalid-keyusage.p12");
    final TslSigner tslSignerInvalid =
        tslSignerBuilder
            .tslToSign(tslEcc)
            .tslSignerP12(invalidKeyUsageSigner)
            .checkSignerKeyUsage(true)
            .build();
    assertThatThrownBy(tslSignerInvalid::sign)
        .hasMessage("Fehler bei erstellen der XAdES Signatur.")
        .isInstanceOf(GemPkiRuntimeException.class)
        .cause()
        .isInstanceOf(SigningCertKeyUsageException.class);

    final TslSigner tslSignerValid =
        tslSignerBuilder
            .tslToSign(tslEcc)
            .tslSignerP12(invalidKeyUsageSigner)
            .checkSignerKeyUsage(false)
            .build();
    assertDoesNotThrow(tslSignerValid::sign);
  }

  @ParameterizedTest
  @ValueSource(strings = {"TSL-Signing-Unit-8_expired.p12", "TSL-Signing-Unit-8_not-yet-valid.p12"})
  void verifyCheckValidityDisabled(final String certName) {
    final Document tslEcc = TestUtils.getDefaultTslAsDoc();
    final P12Container invalidValiditySigner = readP12("GEM.TSL-CA8/" + certName);
    final TslSigner tslSignerInvalid =
        tslSignerBuilder.tslToSign(tslEcc).tslSignerP12(invalidValiditySigner).build();

    assertThatThrownBy(tslSignerInvalid::sign)
        .hasMessage("Fehler bei erstellen der XAdES Signatur.")
        .isInstanceOf(GemPkiRuntimeException.class)
        .cause()
        .isInstanceOf(SigningCertValidityException.class);

    final TslSigner tslSignerValid =
        tslSignerBuilder
            .tslToSign(tslEcc)
            .tslSignerP12(invalidValiditySigner)
            .checkSignerValidity(false)
            .build();
    assertDoesNotThrow(tslSignerValid::sign);
  }

  @Test
  void bouncyCastleProviderIsSetRsa() {
    // now remove the BouncyCastleProvider
    final Document tslRsa = TestUtils.getTslAsDoc(FILE_NAME_TSL_RSA_DEFAULT);
    final P12Container signerRsa = readP12(SIGNER_PATH_RSA);
    final TslSigner tslSigner = tslSignerBuilder.tslToSign(tslRsa).tslSignerP12(signerRsa).build();

    assertDoesNotThrow(tslSigner::sign);

    // now remove the BouncyCastleProvider
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    assertThatThrownBy(tslSigner::sign)
        .isInstanceOf(GemPkiRuntimeException.class)
        .cause()
        .isInstanceOf(XAdES4jXMLSigException.class)
        .hasMessage(
            "The requested algorithm http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1 does"
                + " not exist. Original Message was:"
                + " org.apache.xml.security.algorithms.implementations.SignatureBaseRSA$SignatureRSASHA256MGF1");
    // ... and then restore the BouncyCastleProvider

    GemLibPkiUtils.setBouncyCastleProvider();
  }

  @Test
  void bouncyCastleProviderIsSetEcc() {
    // now remove the BouncyCastleProvider
    final Document tslEcc = TestUtils.getDefaultTslAsDoc();
    final P12Container signerEcc = readP12(SIGNER_PATH_ECC);
    final TslSigner tslSigner = tslSignerBuilder.tslToSign(tslEcc).tslSignerP12(signerEcc).build();

    assertDoesNotThrow(tslSigner::sign);

    // now remove the BouncyCastleProvider
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    assertThatThrownBy(tslSigner::sign)
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Fehler bei erstellen der XAdES Signatur.")
        .cause()
        .isInstanceOf(XAdES4jXMLSigException.class)
        .hasMessageStartingWith("Curve not supported: org.bouncycastle.jce.spec.ECNamedCurveSpec@");
    // ... and then restore the BouncyCastleProvider

    GemLibPkiUtils.setBouncyCastleProvider();
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
    assertThat(TslValidator.checkSignature(tslEcc, TRUST_ANCHOR_ECC)).isTrue();
  }

  @Test
  void verifySignatureEccException()
      throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {

    final KeyStore trustAnchorStore = KeyStore.getInstance(KeyStore.getDefaultType());
    final KeyStore trustAnchorStoreMock = spy(trustAnchorStore);

    Mockito.doThrow(new IOException()).when(trustAnchorStoreMock).load(any());

    try (final MockedStatic<KeyStore> keyStoreStatic = Mockito.mockStatic(KeyStore.class)) {
      keyStoreStatic.when(() -> KeyStore.getInstance(any())).thenReturn(trustAnchorStoreMock);

      assertThatThrownBy(() -> TslValidator.checkSignature(tslEcc, TRUST_ANCHOR_ECC))
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("TSL signature verification failed.");
    }
  }

  @Test
  void verifySignatureEccBytesValid() {
    final byte[] tslBytes = docToBytes(tslEcc);
    assertThat(TslValidator.checkSignature(tslBytes, TRUST_ANCHOR_ECC)).isTrue();
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
    final Document tslAltTa = TestUtils.getTslAsDoc(FILE_NAME_TSL_RSA_ALT_TA);
    assertThat(TslValidator.checkSignature(tslAltTa, trustAnchorRsa)).isFalse();
  }

  @Test
  void verifySignatureMissing() {
    final Element signature = TslUtils.getSignature(tslRsa);
    final Element tslNew = (Element) signature.getParentNode();
    tslNew.removeChild(signature);
    assertThat(TslValidator.checkSignature(tslNew.getOwnerDocument(), trustAnchorRsa)).isFalse();
  }

  @Test
  void nonNull() {

    assertNonNullParameter(() -> tslSignerBuilder.tslToSign(null), "tslToSign");

    assertNonNullParameter(() -> tslSignerBuilder.tslSignerP12(null), "tslSignerP12");
  }
}
