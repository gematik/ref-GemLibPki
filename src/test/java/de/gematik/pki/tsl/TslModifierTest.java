/*
 * Copyright (c) 2021 gematik GmbH
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

import static de.gematik.pki.utils.ResourceReader.getFilePathFromResources;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import de.gematik.pki.exception.GemPkiException;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.Month;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Scanner;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslModifierTest {

    private static final String FILE_NAME_TSL = "tsls/valid/TSL-test.xml";
    TrustStatusListType tsl;

    @BeforeEach
    void setup() throws GemPkiException, IOException, URISyntaxException {
        tsl = TslReader.getTsl(getFilePathFromResources(FILE_NAME_TSL)).orElseThrow();
    }

    @SneakyThrows
    @Test
    void modifyAllSspsOfOneTsp() {
        final Path destFilePath = Path.of("target/TSL-test_modifiedSsp.xml");
        final String gematikTestTspName = "gematik Gesellschaft für Telematikanwendungen der Gesundheitskarte mbH";
        final int modifiedSspAmountexpected = 15;
        final String newSsp = "http://my.new-service-supply-point:8080/ocsp";
        final String newSspElement = "<ServiceSupplyPoint>" + newSsp + "</ServiceSupplyPoint>";

        TslModifier.modifySspForCAsOfTsp(tsl, gematikTestTspName, newSsp);
        final TslInformationProvider tslInformationProvider = new TslInformationProvider(tsl);

        // get sample and compare
        final int sampleTspServiceIdx = 0;
        final int sampleSspIdx = 0;

        assertThat(
            tslInformationProvider
                .getTspServicesForTsp(gematikTestTspName, TslConstants.STI_CA_LIST)
                .get(sampleTspServiceIdx)
                .getTspServiceType().getServiceInformation()
                .getServiceSupplyPoints().getServiceSupplyPoint().get(sampleSspIdx).getValue()
        ).isEqualTo(newSsp);

        TslWriter.write(tsl, destFilePath);
        assertThat(countStringInFile(destFilePath, newSspElement)).isEqualTo(modifiedSspAmountexpected);
    }

    @Test
    void modifySequenceNr() throws GemPkiException {
        final Path destFileName = Path.of("target/TSL-test_modifiedSequenceNr.xml");
        final int newSequenceNr = 4732;
        TslModifier.modifySequenceNr(tsl, newSequenceNr);
        TslWriter.write(tsl, destFileName);
        assertThat(tsl.getSchemeInformation().getTSLSequenceNumber()).isEqualTo(BigInteger.valueOf(newSequenceNr));
    }

    @SneakyThrows
    @Test
    void modifyNextUpdate() {
        final Path path = Path.of("target/TSL-test_modifiedNextUpdate.xml");
        // 2028-12-24T17:30:00
        final LocalDateTime nextUpdateLdt = LocalDateTime.of(2028, Month.DECEMBER, 24, 17, 30, 0);
        // 2028-12-24T17:30:00Z
        final ZonedDateTime nextUpdateZdtUtc = ZonedDateTime.of(nextUpdateLdt, ZoneOffset.UTC);

        TslModifier.modifyNextUpdate(tsl, nextUpdateZdtUtc);
        TslWriter.write(tsl, path);
        assertThat(TslReader.getNextUpdate(tsl)).isEqualTo(nextUpdateZdtUtc);
    }

    @SneakyThrows
    @Test
    void modifyIssueDate() {
        final Path path = Path.of("target/TSL-test_modifiedIssueDate.xml");
        final LocalDateTime issueDateLdt = LocalDateTime.of(2027, Month.APRIL, 30, 3, 42, 0);
        final ZonedDateTime issueDateZdUtc = ZonedDateTime.of(issueDateLdt, ZoneOffset.UTC);

        TslModifier.modifyIssueDate(tsl, issueDateZdUtc);
        TslWriter.write(tsl, path);
        assertThat(TslReader.getIssueDate(tsl)).isEqualTo(issueDateZdUtc);
    }

    @SneakyThrows
    @Test
    void setNextUpdateToNextMonthAfterIssueDate() {
        final Path path = Path.of("target/TSL-test_modifiedIssueDateAndNextUpdate.xml");
        final ZonedDateTime issueDateZdUtc = ZonedDateTime.parse("2030-04-22T10:00:00Z");

        TslModifier.modifyIssueDateAndRelatedNextUpdate(tsl, issueDateZdUtc, 30);
        TslWriter.write(tsl, path);
        assertThat(TslReader.getIssueDate(tsl)).isEqualTo(issueDateZdUtc);
        final ZonedDateTime nextUpdate = TslReader.getNextUpdate(tsl);
        assertThat(nextUpdate.getMonth()).isEqualTo(Month.MAY);
        assertThat(nextUpdate.toInstant().toString()).isEqualTo("2030-05-22T10:00:00Z");
    }

    @Test
    void modifyTslDownloadUrls() throws GemPkiException {
        final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrls.xml");
        final String tslDnlUrlPrimary = "http://download-primary/myNewTsl.xml";
        final String tslDnlUrlBackup = "http://download-backup/myNewTsl.xml";
        TslModifier.setOtherTSLPointers(tsl,
            Map.of(TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY, tslDnlUrlPrimary, TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP, tslDnlUrlBackup));
        TslWriter.write(tsl, path);

        assertThat(TslReader.getTslDownloadUrlPrimary(tsl)).isEqualTo(tslDnlUrlPrimary);
        assertThat(TslReader.getTslDownloadUrlBackup(tsl)).isEqualTo(tslDnlUrlBackup);
    }

    /**
     * Actually a test of TslModifier and TslReader. TslModifier writes a non gematik oid, TslReader cannot work with such a TSL.
     */
    @Test
    void modifyTslDownloadUrlsUnknownOidBackup() throws GemPkiException {
        final Path destFilePath = Path.of("target/TSL-test_modifiedTslDownloadUrls.xml");
        final String tslDnlUrlPrimary = "http://download-primary/myNewTsl.xml";
        final String tslDnlUrlBackup = "http://download-backup/myNewTsl.xml";
        TslModifier.setOtherTSLPointers(tsl,
            Map.of(TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY, tslDnlUrlPrimary, TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP + ".00", tslDnlUrlBackup));
        TslWriter.write(tsl, destFilePath);

        assertThat(TslReader.getTslDownloadUrlPrimary(tsl)).isEqualTo(tslDnlUrlPrimary);
        assertThatThrownBy(
            () -> TslReader.getTslDownloadUrlBackup(tsl))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining(TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP);
    }

    @Test
    void modifyTslDownloadUrlPrimary() throws GemPkiException {
        final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrlPrimary.xml");
        final String tslDnlUrlPrimary = "http://download-primary-only/myNewTsl.xml";

        TslModifier.modifyTslDownloadUrlPrimary(tsl, tslDnlUrlPrimary);
        TslWriter.write(tsl, path);

        assertThat(TslReader.getTslDownloadUrlPrimary(tsl)).isEqualTo(tslDnlUrlPrimary);
    }

    @Test
    void modifyTslDownloadUrlbackup() throws GemPkiException {
        final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrlBackup.xml");
        final String tslDnlUrlBackup = "http://download-backup-only/myNewTsl.xml";

        TslModifier.modifyTslDownloadUrlBackup(tsl, tslDnlUrlBackup);
        TslWriter.write(tsl, path);

        assertThat(TslReader.getTslDownloadUrlBackup(tsl)).isEqualTo(tslDnlUrlBackup);
    }

    private static int countStringInFile(@NonNull final Path path, @NonNull final String expected) throws IOException {
        final Scanner scanner = new Scanner(path);
        int cnt = 0;
        while (scanner.hasNextLine()) {
            final String line = scanner.nextLine();
            cnt += StringUtils.countMatches(line, expected);
        }
        return cnt;
    }

    @Test
    void generateTslId() {
        final ZonedDateTime issueDateZdUtc = ZonedDateTime.parse("2027-07-21T11:00:00Z");
        assertThat(TslModifier.generateTslId(42, issueDateZdUtc)).isEqualTo("ID34220270721110000Z");
    }
}
