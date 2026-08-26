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

package de.gematik.pki.gemlibpki.commons.utils;

import static de.gematik.pki.gemlibpki.commons.TestConstants.P12_PASSWORD;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.FILE_NAME_TSL_DEFAULT_NON_QES;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_DEFAULT_QES;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_OCSP_SIGNER;
import static org.awaitility.Awaitility.await;

import de.gematik.pki.gemlibpki.commons.TestConstantsNonQes;
import de.gematik.pki.gemlibpki.commons.TestConstantsQes;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator;
import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TslReader;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import eu.europa.esig.trustedlist.jaxb.tsl.AttributedNonEmptyURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceSupplyPointsType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import lombok.NonNull;
import org.assertj.core.api.AssertionsForClassTypes;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xmlunit.assertj3.XmlAssert;
import org.xmlunit.util.Predicate;

public class TestUtils {

  public static void assertXmlEqual(final Object actual, final Object expected) {

    final Predicate<Node> ignoreSignatureElement =
        node -> !node.getNodeName().contains(":Signature");

    XmlAssert.assertThat(actual)
        .and(expected)
        .withNodeFilter(ignoreSignatureElement)
        .ignoreWhitespace()
        .areIdentical();
  }

  public static void assertNonNullParameter(
      final ThrowingCallable shouldRaiseThrowable, @NonNull final String paramName) {
    AssertionsForClassTypes.assertThatThrownBy(shouldRaiseThrowable)
        .isInstanceOf(NullPointerException.class)
        .hasMessage(paramName + " is marked non-null but is null");
  }

  public static void overwriteSspUrls(final List<TspService> tspServiceList, final String newSsp) {
    final ServiceSupplyPointsType serviceSupplyPointsType = new ServiceSupplyPointsType();
    final AttributedNonEmptyURIType newSspElement = new AttributedNonEmptyURIType();
    newSspElement.setValue(newSsp);
    serviceSupplyPointsType.getServiceSupplyPoint().add(newSspElement);
    tspServiceList.forEach(
        tspService ->
            tspService
                .getTspServiceType()
                .getServiceInformation()
                .setServiceSupplyPoints(serviceSupplyPointsType));
  }

  public static TrustStatusListType getTslUnsigned(final String tslFilename) {
    return TslReader.getTslUnsigned(
        ResourceReader.getFilePathFromResources(tslFilename, TestUtils.class));
  }

  public static TrustStatusListType getDefaultTslUnsignedNonQes() {
    return TslReader.getTslUnsigned(
        ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT_NON_QES, TestUtils.class));
  }

  public static TrustStatusListType getDefaultTslUnsignedQes() {
    return TslReader.getTslUnsigned(
        ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT_QES, TestUtils.class));
  }

  public static TrustStatusListType getAdditionalCaDefaultTslUnsignedQes() {
    return TslReader.getTslUnsigned(
        ResourceReader.getFilePathFromResources(
            FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA, TestUtils.class));
  }

  public static TrustStatusListType getAdditionalOcspSignerDefaultTslUnsignedQes() {
    return TslReader.getTslUnsigned(
        ResourceReader.getFilePathFromResources(
            FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_OCSP_SIGNER, TestUtils.class));
  }

  public static Document getDefaultTslAsDocNonQes() {
    return getTslAsDoc(FILE_NAME_TSL_DEFAULT_NON_QES);
  }

  public static Document getDefaultTslAsDocQes() {
    return getTslAsDoc(FILE_NAME_TSL_DEFAULT_QES);
  }

  public static Document getTslAsDoc(final String filename) {
    return TslReader.getTslAsDoc(
        ResourceReader.getFilePathFromResources(filename, TestUtils.class));
  }

  public static List<TspService> getDefaultTspServiceListNonQes() {
    return new TslInformationProvider(getDefaultTslUnsignedNonQes()).getTspServices();
  }

  public static List<TspService> getDefaultTspServiceListQes() {
    return new TslInformationProvider(getDefaultTslUnsignedQes()).getTspServices();
  }

  public static List<TspService> getAlternativeTspServiceListQes() {
    return new TslInformationProvider(getAdditionalCaDefaultTslUnsignedQes()).getTspServices();
  }

  public static void waitSeconds(final long seconds) {
    await()
        .atMost(Duration.ofSeconds(seconds + 1))
        .pollInterval(Duration.ofMillis(10))
        .until(secondsElapsed(seconds, ZonedDateTime.now()));
  }

  private static Callable<Boolean> secondsElapsed(final long seconds, final ZonedDateTime start) {
    return () -> start.plusSeconds(seconds).isBefore(ZonedDateTime.now());
  }

  public static X509Certificate readCertNonQes(final String filename) {
    return CertificateProvider.getX509Certificate(TestConstantsNonQes.CERT_DIR_NON_QES + filename);
  }

  public static X509Certificate readCertQes(final String filename) {
    return CertificateProvider.getX509Certificate(TestConstantsQes.CERT_DIR_QES + filename);
  }

  public static Path createLogFileInTarget(final String prefix) throws IOException {
    final String timestamp =
        ZonedDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));

    final Path filePath = Path.of("target/%s_%s.dat".formatted(prefix, timestamp));

    if (Files.exists(filePath)) {
      Files.delete(filePath);
    }

    Files.createFile(filePath);

    return filePath;
  }

  public static P12Container readP12nonQes(final String p12Path) {
    return Objects.requireNonNull(
        P12Reader.getContentFromP12(
            Path.of(TestConstantsNonQes.CERT_DIR_NON_QES, p12Path), P12_PASSWORD));
  }

  public static P12Container readP12Qes(final String p12Path) {
    return Objects.requireNonNull(
        P12Reader.getContentFromP12(Path.of(TestConstantsQes.CERT_DIR_QES, p12Path), P12_PASSWORD));
  }

  public static byte[] readP12QesAsBytes(final String p12Path) {
    return GemLibPkiUtils.readContent(Path.of(TestConstantsQes.CERT_DIR_QES, p12Path));
  }

  public static OCSPResp generateOcspResponse(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final X509Certificate x509IssuerCert,
      final P12Container responseSigner) {
    return generateOcspResponse(x509EeCert, x509IssuerCert, responseSigner, null);
  }

  public static OCSPResp generateOcspResponse(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final X509Certificate x509IssuerCert,
      final P12Container responseSigner,
      final Extension extension) {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(x509EeCert, x509IssuerCert, extension);
    return OcspResponseGenerator.builder()
        .signer(responseSigner)
        .build()
        .generate(ocspReq, x509EeCert, x509IssuerCert);
  }

  public static OCSPResp generateOcspResponseWithTimeStamps(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final X509Certificate x509IssuerCert,
      final P12Container responseSigner,
      final Extension extension,
      final ZonedDateTime thisUpdate,
      final ZonedDateTime producedAt,
      final ZonedDateTime nextUpdate,
      final CertificateStatus certificateStatus) {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(x509EeCert, x509IssuerCert, extension);
    return OcspResponseGenerator.builder()
        .signer(responseSigner)
        .thisUpdate(thisUpdate)
        .producedAt(producedAt)
        .nextUpdate(nextUpdate)
        .build()
        .generate(ocspReq, x509EeCert, x509IssuerCert, certificateStatus);
  }
}
