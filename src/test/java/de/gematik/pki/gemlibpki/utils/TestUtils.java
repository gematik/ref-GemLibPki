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

package de.gematik.pki.gemlibpki.utils;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static org.awaitility.Awaitility.await;

import de.gematik.pki.gemlibpki.TestConstants;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.tsl.TspService;
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

  public static TrustStatusListType getTsl(final String tslFilename) {
    return TslReader.getTsl(ResourceReader.getFilePathFromResources(tslFilename, TestUtils.class));
  }

  public static TrustStatusListType getDefaultTsl() {
    return TslReader.getTsl(
        ResourceReader.getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT, TestUtils.class));
  }

  public static Document getDefaultTslAsDoc() {
    return getTslAsDoc(FILE_NAME_TSL_ECC_DEFAULT);
  }

  public static Document getTslAsDoc(final String filename) {
    return TslReader.getTslAsDoc(
        ResourceReader.getFilePathFromResources(filename, TestUtils.class));
  }

  public static List<TspService> getDefaultTspServiceList() {

    return new TslInformationProvider(getDefaultTsl()).getTspServices();
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

  public static X509Certificate readCert(final String filename) {
    return CertificateProvider.getX509Certificate(TestConstants.CERT_DIR + filename);
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

  public static P12Container readP12(final String p12Path) {
    return Objects.requireNonNull(
        P12Reader.getContentFromP12(
            Path.of(TestConstants.CERT_DIR, p12Path), TestConstants.P12_PASSWORD));
  }
}
