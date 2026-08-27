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

import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_TSL_CA51;
import static de.gematik.pki.gemlibpki.commons.tsl.TslConverter.docToBytes;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.readP12nonQes;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.w3c.dom.Document;
import xades4j.XAdES4jXMLSigException;
import xades4j.production.SigningCertKeyUsageException;
import xades4j.production.SigningCertValidityException;
import xades4j.production.XadesBesSigningProfile;
import xades4j.utils.XadesProfileResolutionException;

class TslSignerNonQesTest {

  public static final String SIGNER_PATH_NON_QES = "GEM.TSL-CA51/TSL-Signing-Unit-51-TEST-ONLY.p12";

  private static Document tslNonQes;

  private final TslSignerNonQes.TslSignerNonQesBuilder tslSignerBuilder = TslSignerNonQes.builder();

  @BeforeEach
  public void setup() {

    GemLibPkiUtils.setBouncyCastleProvider();

    tslNonQes = TestUtils.getDefaultTslAsDocNonQes();

    final P12Container signerNonQes = readP12nonQes(SIGNER_PATH_NON_QES);
    tslSignerBuilder.tslToSign(tslNonQes).tslSignerP12(signerNonQes).build().sign();
  }

  @Test
  void sign_whenSignerCertificateHasInvalidKeyUsageAndCheckIsToggled_thenThrowsOnlyWhenEnabled() {
    final Document tslEcc = TestUtils.getDefaultTslAsDocNonQes();
    final P12Container invalidKeyUsageSigner =
        readP12nonQes("GEM.TSL-CA51/TSL-Signing-Unit-51_invalid-keyusage.p12");
    final TslSignerNonQes tslSignerNonQesInvalid =
        tslSignerBuilder
            .tslToSign(tslEcc)
            .tslSignerP12(invalidKeyUsageSigner)
            .checkSignerKeyUsage(true)
            .build();
    assertThatThrownBy(tslSignerNonQesInvalid::sign)
        .hasMessage("Fehler bei erstellen der XAdES Signatur.")
        .isInstanceOf(GemPkiRuntimeException.class)
        .cause()
        .isInstanceOf(SigningCertKeyUsageException.class);

    final TslSignerNonQes tslSignerNonQesValid =
        tslSignerBuilder
            .tslToSign(tslEcc)
            .tslSignerP12(invalidKeyUsageSigner)
            .checkSignerKeyUsage(false)
            .build();
    assertDoesNotThrow(tslSignerNonQesValid::sign);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"TSL-Signing-Unit-51_expired.p12", "TSL-Signing-Unit-51_not-yet-valid.p12"})
  void sign_whenSignerCertificateValidityIsInvalidAndCheckIsToggled_thenThrowsOnlyWhenEnabled(
      final String certName) {
    final Document tslEcc = TestUtils.getDefaultTslAsDocNonQes();
    final P12Container invalidValiditySigner = readP12nonQes("GEM.TSL-CA51/" + certName);
    final TslSignerNonQes tslSignerNonQesInvalid =
        tslSignerBuilder.tslToSign(tslEcc).tslSignerP12(invalidValiditySigner).build();

    assertThatThrownBy(tslSignerNonQesInvalid::sign)
        .hasMessage("Fehler bei erstellen der XAdES Signatur.")
        .isInstanceOf(GemPkiRuntimeException.class)
        .cause()
        .isInstanceOf(SigningCertValidityException.class);

    final TslSignerNonQes tslSignerNonQesValid =
        tslSignerBuilder
            .tslToSign(tslEcc)
            .tslSignerP12(invalidValiditySigner)
            .checkSignerValidity(false)
            .build();
    assertDoesNotThrow(tslSignerNonQesValid::sign);
  }

  @Test
  void
      sign_whenBouncyCastleProviderIsPresentThenRemoved_thenSucceedsThenThrowsGemPkiRuntimeException() {
    // now remove the BouncyCastleProvider
    final Document tslEcc = TestUtils.getDefaultTslAsDocNonQes();
    final P12Container signerEcc = readP12nonQes(SIGNER_PATH_NON_QES);
    final TslSignerNonQes tslSignerNonQes =
        tslSignerBuilder.tslToSign(tslEcc).tslSignerP12(signerEcc).build();

    assertDoesNotThrow(tslSignerNonQes::sign);

    // now remove the BouncyCastleProvider
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    assertThatThrownBy(tslSignerNonQes::sign)
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Fehler bei erstellen der XAdES Signatur.")
        .cause()
        .isInstanceOf(XAdES4jXMLSigException.class)
        .hasMessageStartingWith("Curve not supported: org.bouncycastle.jce.spec.ECNamedCurveSpec@");
  }

  @Test
  void checkNonQesTslSignatureWithTrustAnchor_whenSignedDocumentIsValid_thenReturnsTrue() {
    assertThat(
            TslValidator.checkNonQesTslSignatureWithTrustAnchor(
                tslNonQes, VALID_ISSUER_CERT_TSL_CA51))
        .isTrue();
  }

  @Test
  void
      checkNonQesTslSignatureWithTrustAnchor_whenKeyStoreLoadingFails_thenThrowsGemPkiRuntimeException()
          throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {

    final KeyStore trustAnchorStore = KeyStore.getInstance(KeyStore.getDefaultType());
    final KeyStore trustAnchorStoreMock = spy(trustAnchorStore);

    Mockito.doThrow(new IOException()).when(trustAnchorStoreMock).load(any());

    try (final MockedStatic<KeyStore> keyStoreStatic = Mockito.mockStatic(KeyStore.class)) {
      keyStoreStatic.when(() -> KeyStore.getInstance(any())).thenReturn(trustAnchorStoreMock);

      assertThatThrownBy(
              () ->
                  TslValidator.checkNonQesTslSignatureWithTrustAnchor(
                      tslNonQes, VALID_ISSUER_CERT_TSL_CA51))
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("TSL signature verification failed.");
    }
  }

  @Test
  void checkNonQesTslSignatureWithTrustAnchor_whenSignedBytesAreValid_thenReturnsTrue() {
    final byte[] tslBytes = docToBytes(tslNonQes);
    assertThat(
            TslValidator.checkNonQesTslSignatureWithTrustAnchor(
                tslBytes, VALID_ISSUER_CERT_TSL_CA51))
        .isTrue();
  }

  @Test
  void builderMethods_whenRequiredArgumentsAreNull_thenThrowsOnNullParameter() {

    assertNonNullParameter(() -> tslSignerBuilder.tslToSign(null), "tslToSign");

    assertNonNullParameter(() -> tslSignerBuilder.tslSignerP12(null), "tslSignerP12");
  }

  @Test
  void sign_whenXadesProfileCreationFails_thenThrowsGemPkiRuntimeException() {
    final P12Container signerEcc = readP12nonQes(SIGNER_PATH_NON_QES);
    final TslSignerNonQes tslSignerNonQes =
        tslSignerBuilder.tslToSign(tslNonQes).tslSignerP12(signerEcc).build();

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

      assertThatThrownBy(tslSignerNonQes::sign)
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("Fehler beim erstellen des XAdES Profil Objektes.")
          .cause()
          .isInstanceOf(XadesProfileResolutionException.class);
    }
  }

  @Test
  void sign_whenValidSignerIsUsedForDefaultTsl_thenWritesVerifiableSignedFile() {
    final String destFileName = "target/TSL_default_signer_51_SSP_Localhost.xml";
    final Document tslDefaultEcc = TestUtils.getDefaultTslAsDocNonQes();
    final P12Container signerEcc =
        readP12nonQes("ti20/GEM.TSL-CA51/TSL-Signing-Unit-51-SSP-Localhost-TEST-ONLY.p12");

    tslSignerBuilder.tslToSign(tslDefaultEcc).tslSignerP12(signerEcc).build().sign();
    TslWriter.write(tslDefaultEcc, Path.of(destFileName));
    final byte[] tslBytes = docToBytes(tslDefaultEcc);
    assertThat(
            TslValidator.checkNonQesTslSignatureWithTrustAnchor(
                tslBytes, VALID_ISSUER_CERT_TSL_CA51))
        .isTrue();
  }
}
