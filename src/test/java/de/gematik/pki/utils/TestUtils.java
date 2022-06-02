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

package de.gematik.pki.utils;

import de.gematik.pki.common.OcspResponderMock;
import de.gematik.pki.ocsp.OcspRequestGenerator;
import de.gematik.pki.tsl.TspService;
import eu.europa.esig.trustedlist.jaxb.tsl.AttributedNonEmptyURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceSupplyPointsType;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.SneakyThrows;
import org.bouncycastle.cert.ocsp.OCSPReq;

public class TestUtils {

    @SneakyThrows
    public static void configureOcspResponderMockForOcspRequest(final X509Certificate x509EeCert, final OcspResponderMock ocspResponderMock) {
        final X509Certificate VALID_X509_ISSUER_CERT = CertificateProvider.getX509Certificate("src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");
        final OCSPReq ocspReq = OcspRequestGenerator.generateSingleOcspRequest(x509EeCert, VALID_X509_ISSUER_CERT);
        ocspResponderMock.configureForOcspRequest(ocspReq, x509EeCert);
    }

    @SneakyThrows
    public static void overwriteSspUrls(final List<TspService> tspServiceList, final String newSsp) {
        final ServiceSupplyPointsType serviceSupplyPointsType = new ServiceSupplyPointsType();
        final AttributedNonEmptyURIType newSspElement = new AttributedNonEmptyURIType();
        newSspElement.setValue(newSsp);
        serviceSupplyPointsType.getServiceSupplyPoint().add(newSspElement);
        tspServiceList.forEach(tspService -> tspService.getTspServiceType().getServiceInformation()
            .setServiceSupplyPoints(serviceSupplyPointsType));
    }
}
