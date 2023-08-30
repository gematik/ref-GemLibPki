/*
 * Copyright 2023 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.tsl.TslUtils.tslDownloadUrlMatchesOid;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.NextUpdateType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.math.BigInteger;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import javax.xml.datatype.XMLGregorianCalendar;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.w3c.dom.Document;

/**
 * Class to read a TSL file, put it in an object structure and get different information from it.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TslReader {

  /**
   * @param tslPath File path to TSL
   * @return A TSL as Document
   */
  public static Document getTslAsDoc(@NonNull final Path tslPath) {
    return TslConverter.bytesToDoc(GemLibPkiUtils.readContent(tslPath));
  }

  /**
   * Get a list of {@link TrustStatusListType} to a parameterized TSL file.
   *
   * @param tslPath file name
   * @return a TrustServiceStatusList contains issuer certificates among other things
   */
  public static TrustStatusListType getTslUnsigned(@NonNull final Path tslPath) {
    return TslConverter.bytesToTslUnsigned(GemLibPkiUtils.readContent(tslPath));
  }

  /**
   * Read sequence number from given TSL
   *
   * @param tsl A TSL
   * @return TSL sequence number
   */
  public static BigInteger getTslSeqNr(@NonNull final TrustStatusListType tsl) {
    return tsl.getSchemeInformation().getTSLSequenceNumber();
  }

  /**
   * Read "NextUpdate" from given TSL
   *
   * @param tsl A TSL
   * @return NextUpdate
   */
  public static ZonedDateTime getNextUpdate(@NonNull final TrustStatusListType tsl) {
    final NextUpdateType nextUpdate = tsl.getSchemeInformation().getNextUpdate();
    if (nextUpdate == null) {
      throw new GemPkiRuntimeException("NextUpdate not found in TSL.");
    }
    return (nextUpdate.getDateTime().toGregorianCalendar().toZonedDateTime());
  }

  /**
   * Read "ListIssueDateTime" from given TSL
   *
   * @param tsl A TSL
   * @return IssueDate
   */
  public static ZonedDateTime getIssueDate(@NonNull final TrustStatusListType tsl) {
    final XMLGregorianCalendar xmlIssueDate = tsl.getSchemeInformation().getListIssueDateTime();
    return xmlIssueDate.toGregorianCalendar().toZonedDateTime();
  }

  /**
   * Deliver a reference to OtherTSLPointersType (contains all TSLLocation)
   *
   * @param tsl A TSL
   * @return a reference to OtherTSLPointersType
   */
  public static OtherTSLPointersType getOtherTslPointers(@NonNull final TrustStatusListType tsl) {
    return tsl.getSchemeInformation().getPointersToOtherTSL();
  }

  /**
   * Read the primary TSLLocation
   *
   * @param tsl A TSL
   * @return The primary TSLLocation
   */
  public static String getTslDownloadUrlPrimary(@NonNull final TrustStatusListType tsl) {
    return getTslDownloadUrl(tsl, TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY);
  }

  /**
   * Read the backup TSLLocation
   *
   * @param tsl A TSL
   * @return The backup TSLLocation
   */
  public static String getTslDownloadUrlBackup(@NonNull final TrustStatusListType tsl) {
    return getTslDownloadUrl(tsl, TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP);
  }

  private static String getTslDownloadUrl(final TrustStatusListType tsl, final String oid) {
    return getOtherTslPointers(tsl).getOtherTSLPointer().stream()
        .filter(tslDownloadUrlMatchesOid(oid))
        .findFirst()
        .orElseThrow(() -> new GemPkiRuntimeException("TSL enthaelt nicht OID: " + oid))
        .getTSLLocation();
  }
}
