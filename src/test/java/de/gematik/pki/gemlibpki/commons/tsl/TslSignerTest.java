/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.commons.tsl;

import static de.gematik.pki.gemlibpki.commons.TestConstants.FILE_NAME_TSL_ECC_ALT_TA;
import static de.gematik.pki.gemlibpki.commons.TestConstants.FILE_NAME_TSL_ECC_DEFAULT_WITHOUT_OCSP_SIGNER_57;
import static de.gematik.pki.gemlibpki.commons.TestConstants.VALID_ISSUER_CERT_TSL_CA51;
import static de.gematik.pki.gemlibpki.commons.TestConstants.VALID_ISSUER_CERT_TSL_CA52;
import static de.gematik.pki.gemlibpki.commons.tsl.TslConverter.docToBytes;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.readP12;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.tsl.TslSigner.TslSignerBuilder;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.commons.utils.P12Container;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import java.io.IOException;
import java.nio.file.Path;
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
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import xades4j.XAdES4jXMLSigException;
import xades4j.production.SigningCertKeyUsageException;
import xades4j.production.SigningCertValidityException;
import xades4j.production.XadesBesSigningProfile;
import xades4j.utils.XadesProfileResolutionException;

class TslSignerTest {

  public static final String SIGNER_PATH_ECC = "GEM.TSL-CA51/TSL-Signing-Unit-51-TEST-ONLY.p12";

  private static Document tslEcc;

  private static final X509Certificate trustAnchorEcc =
      TestUtils.readCert("GEM.TSL-CA51/GEM.TSL-CA51-TEST-ONLY.pem");
  private final TslSignerBuilder tslSignerBuilder = TslSigner.builder();

  @BeforeEach
  public void setup() {

    GemLibPkiUtils.setBouncyCastleProvider();

    tslEcc = TestUtils.getDefaultTslAsDoc();

    final P12Container signerEcc = readP12(SIGNER_PATH_ECC);
    tslSignerBuilder.tslToSign(tslEcc).tslSignerP12(signerEcc).build().sign();
  }

  @Test
  void verifyCheckKeyUsageDisabled() {
    final Document tslEcc = TestUtils.getDefaultTslAsDoc();
    final P12Container invalidKeyUsageSigner =
        readP12("GEM.TSL-CA51/TSL-Signing-Unit-51_invalid-keyusage.p12");
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
  @ValueSource(
      strings = {"TSL-Signing-Unit-51_expired.p12", "TSL-Signing-Unit-51_not-yet-valid.p12"})
  void verifyCheckValidityDisabled(final String certName) {
    final Document tslEcc = TestUtils.getDefaultTslAsDoc();
    final P12Container invalidValiditySigner = readP12("GEM.TSL-CA51/" + certName);
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
  }

  @Test
  void verifySignatureEccValid() {
    assertThat(TslValidator.checkSignature(tslEcc, VALID_ISSUER_CERT_TSL_CA51)).isTrue();
  }

  @Test
  void verifySignatureEccException()
      throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {

    final KeyStore trustAnchorStore = KeyStore.getInstance(KeyStore.getDefaultType());
    final KeyStore trustAnchorStoreMock = spy(trustAnchorStore);

    Mockito.doThrow(new IOException()).when(trustAnchorStoreMock).load(any());

    try (final MockedStatic<KeyStore> keyStoreStatic = Mockito.mockStatic(KeyStore.class)) {
      keyStoreStatic.when(() -> KeyStore.getInstance(any())).thenReturn(trustAnchorStoreMock);

      assertThatThrownBy(() -> TslValidator.checkSignature(tslEcc, VALID_ISSUER_CERT_TSL_CA51))
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("TSL signature verification failed.");
    }
  }

  @Test
  void verifySignatureEccBytesValid() {
    final byte[] tslBytes = docToBytes(tslEcc);
    assertThat(TslValidator.checkSignature(tslBytes, VALID_ISSUER_CERT_TSL_CA51)).isTrue();
  }

  @Test
  void verifySignatureEccInvalid() {
    final NodeList tslSeqNrElem = tslEcc.getElementsByTagName("TSLSequenceNumber");
    assertThat(tslSeqNrElem.getLength()).isPositive();
    assertThat(TslValidator.checkSignature(tslEcc, trustAnchorEcc)).isTrue();
    // destroy signature by modifying text in tsl
    tslSeqNrElem.item(0).setTextContent("notAValidNumber");
    assertThat(TslValidator.checkSignature(tslEcc, trustAnchorEcc)).isFalse();
  }

  @Test
  void verifySignatureWrongTa() {
    final Document tslAltTa = TestUtils.getTslAsDoc(FILE_NAME_TSL_ECC_ALT_TA);
    assertThat(TslValidator.checkSignature(tslAltTa, trustAnchorEcc)).isFalse();
  }

  @Test
  void verifySignatureMissing() {
    final Element signature = TslUtils.getSignature(tslEcc);
    final Element tslNew = (Element) signature.getParentNode();
    tslNew.removeChild(signature);
    assertThat(TslValidator.checkSignature(tslNew.getOwnerDocument(), trustAnchorEcc)).isFalse();
  }

  @Test
  void nonNull() {

    assertNonNullParameter(() -> tslSignerBuilder.tslToSign(null), "tslToSign");

    assertNonNullParameter(() -> tslSignerBuilder.tslSignerP12(null), "tslSignerP12");
  }

  @Test
  void testSign_XadesProfileResolutionException() {
    final P12Container signerEcc = readP12(SIGNER_PATH_ECC);
    final TslSigner tslSigner = tslSignerBuilder.tslToSign(tslEcc).tslSignerP12(signerEcc).build();

    try (final MockedConstruction<XadesBesSigningProfile> ignored =
        Mockito.mockConstruction(
            XadesBesSigningProfile.class,
            (mock, context) -> {
              Mockito.when(mock.withSignatureAlgorithms(any())).thenReturn(mock);
              Mockito.when(mock.withBasicSignatureOptions(any())).thenReturn(mock);
              Mockito.when(mock.newSigner())
                  .thenThrow(
                      new XadesProfileResolutionException("message", new RuntimeException()));
            })) {

      assertThatThrownBy(tslSigner::sign)
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("Fehler beim erstellen des XAdES Profil Objektes.")
          .cause()
          .isInstanceOf(XadesProfileResolutionException.class);
    }
  }

  @Test
  void signTslDefaultAndWriteToFile() {
    final String destFileName = "target/TSL_default_1.xml";
    final Document tslDefaultEcc =
        TestUtils.getTslAsDoc(FILE_NAME_TSL_ECC_DEFAULT_WITHOUT_OCSP_SIGNER_57);
    final P12Container signerEcc =
        readP12("ti20/GEM.TSL-CA51/TSL-Signing-Unit-51-SSP-Localhost-TEST-ONLY.p12");

    tslSignerBuilder.tslToSign(tslDefaultEcc).tslSignerP12(signerEcc).build().sign();
    TslWriter.write(tslDefaultEcc, Path.of(destFileName));
    final byte[] tslBytes = docToBytes(tslDefaultEcc);
    assertThat(TslValidator.checkSignature(tslBytes, VALID_ISSUER_CERT_TSL_CA51)).isTrue();
  }

  @Test
  void signTslDefaultSignerAltCaAndWriteToFile() {
    final String destFileName = "target/TSL_altTA.xml";
    final Document tslDefaultEcc = TestUtils.getDefaultTslAsDoc();
    final P12Container altSignerEcc = readP12("GEM.TSL-CA52/TSL-Signing-Unit-52-TEST-ONLY.p12");

    tslSignerBuilder.tslToSign(tslDefaultEcc).tslSignerP12(altSignerEcc).build().sign();
    TslWriter.write(tslDefaultEcc, Path.of(destFileName));
    final byte[] tslBytes = docToBytes(tslDefaultEcc);
    assertThat(TslValidator.checkSignature(tslBytes, VALID_ISSUER_CERT_TSL_CA52)).isTrue();
  }
}
