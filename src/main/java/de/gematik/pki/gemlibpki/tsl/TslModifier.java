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

import static de.gematik.pki.gemlibpki.tsl.TslHelper.tslDownloadUrlMatchesOid;

import eu.europa.esig.trustedlist.jaxb.tsl.*;
import java.math.BigInteger;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.GregorianCalendar;
import java.util.Map;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;

/** Class for handling tsl modifications */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TslModifier {

  /**
   * Modifies the service supply points (OCSP addresses) of a CA (PKC and SrvCertChange) entry for a
   * given TSP. Other services, such as CRL, OCSP, CVC are not altered
   *
   * @param tsl Source TSL
   * @param tspName destination TrustServiceProvider
   * @param newSsp new ServiceSupplyPoint
   */
  public static void modifySspForCAsOfTsp(
      @NonNull final TrustStatusListType tsl,
      @NonNull final String tspName,
      @NonNull final String newSsp) {
    final AttributedNonEmptyURIType newSspXml = new AttributedNonEmptyURIType();
    newSspXml.setValue(newSsp);
    final ServiceSupplyPointsType newSspType = new ServiceSupplyPointsType();
    newSspType.getServiceSupplyPoint().add(newSspXml);

    tsl.getTrustServiceProviderList()
        .getTrustServiceProvider()
        .forEach(
            tsp -> {
              if (tsp.getTSPInformation()
                  .getTSPName()
                  .getName()
                  .get(0)
                  .getValue()
                  .contains(tspName)) {
                tsp.getTSPServices()
                    .getTSPService()
                    .forEach(
                        service -> {
                          if (TslConstants.STI_CA_LIST.contains(
                              service.getServiceInformation().getServiceTypeIdentifier())) {
                            service.getServiceInformation().setServiceSupplyPoints(newSspType);
                          }
                        });
              }
            });
  }

  /**
   * Modifies the sequence number of a given tsl
   *
   * @param tsl the tsl to modify
   * @param newSeqNr the sequence number to set
   */
  public static void modifySequenceNr(@NonNull final TrustStatusListType tsl, final int newSeqNr) {
    tsl.getSchemeInformation().setTSLSequenceNumber(BigInteger.valueOf(newSeqNr));
  }

  /**
   * Modifies the nextUpdate element of the given tsl
   *
   * @param tsl The tsl to modify
   * @param zdt Utc timestamp of the new nextUpdate value
   * @throws DatatypeConfigurationException if timestamp cannot be parsed
   */
  public static void modifyNextUpdate(
      @NonNull final TrustStatusListType tsl, @NonNull final ZonedDateTime zdt)
      throws DatatypeConfigurationException {
    final XMLGregorianCalendar xmlCal = getXmlGregorianCalendar(zdt);
    final NextUpdateType nextUpdate = new NextUpdateType();
    nextUpdate.setDateTime(xmlCal);
    tsl.getSchemeInformation().setNextUpdate(nextUpdate);
  }

  /**
   * Modifies the issueDate element of the given tsl and sets the nextUpdate element according to a
   * given duration
   *
   * @param tsl The tsl to modify
   * @param issueDate Utc timestamp of the new issueDate value
   * @param daysUntilNextUpdate Integer of the duration in days the tsl will be valid
   *     (issue+duration=nextUpdate)
   * @throws DatatypeConfigurationException if timestamp cannot be parsed
   */
  public static void modifyIssueDateAndRelatedNextUpdate(
      @NonNull final TrustStatusListType tsl,
      @NonNull final ZonedDateTime issueDate,
      final int daysUntilNextUpdate)
      throws DatatypeConfigurationException {
    modifyIssueDate(tsl, issueDate);
    modifyNextUpdate(tsl, issueDate.plusDays(daysUntilNextUpdate));
  }

  /**
   * Modifies the issueDate element of the given tsl
   *
   * @param tsl The tsl to modify
   * @param zdt Utc timestamp of the nes issueDate value
   * @throws DatatypeConfigurationException if timestamp cannot be parsed
   */
  public static void modifyIssueDate(
      @NonNull final TrustStatusListType tsl, @NonNull final ZonedDateTime zdt)
      throws DatatypeConfigurationException {
    final XMLGregorianCalendar xmlCal = getXmlGregorianCalendar(zdt);
    tsl.getSchemeInformation().setListIssueDateTime(xmlCal);
  }

  /** Overwrites complete element "OtherTSLPointersType" in given TSL */
  public static void setOtherTSLPointers(
      @NonNull final TrustStatusListType tsl, @NonNull final Map<String, String> tslPointerValues) {
    final OtherTSLPointersType oTslPointers = new OtherTSLPointersType();
    final int index = 0;
    for (final Map.Entry<String, String> entry : tslPointerValues.entrySet()) {
      oTslPointers
          .getOtherTSLPointer()
          .add(index, createOtherTSLPointerType(entry.getKey(), entry.getValue()));
    }
    setElementOtherTSLPointer(tsl, oTslPointers);
  }

  /** Overwrites the primary download URL in given TSL with given URL. */
  public static void modifyTslDownloadUrlPrimary(
      @NonNull final TrustStatusListType tsl, @NonNull final String url) {
    modifyTslDownloadUrl(tsl, url, TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY);
  }

  /** Overwrites the backup download URL in given TSL with given URL. */
  public static void modifyTslDownloadUrlBackup(
      @NonNull final TrustStatusListType tsl, @NonNull final String url) {
    modifyTslDownloadUrl(tsl, url, TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP);
  }

  /**
   * Generates the String for the tsl id
   *
   * @param seqNumber number of the tsl
   * @param issueDate Timestamp of the issueDate element of the tsl
   * @return New tsl id
   */
  public static String generateTslId(final int seqNumber, @NonNull final ZonedDateTime issueDate) {
    return TslConstants.TSL_ID_PREFIX
        + TslConstants.TSL_VERSION
        + seqNumber
        + issueDate.format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"))
        + issueDate.getZone();
  }

  private static void modifyTslDownloadUrl(
      final TrustStatusListType tsl, final String tslDnlUrlPrimary, final String oid) {
    tsl.getSchemeInformation().getPointersToOtherTSL().getOtherTSLPointer().stream()
        .filter(tslDownloadUrlMatchesOid(oid))
        .findFirst()
        .orElseThrow()
        .setTSLLocation(tslDnlUrlPrimary);
  }

  private static OtherTSLPointerType createOtherTSLPointerType(
      final String oid, final String tslDownloadUrl) {
    final OtherTSLPointerType otpt = new OtherTSLPointerType();
    otpt.setTSLLocation(tslDownloadUrl);

    final MultiLangStringType multiLangStringType = new MultiLangStringType();
    multiLangStringType.setLang("DE");
    multiLangStringType.setValue(oid);

    final AdditionalInformationType additionalInformationType = new AdditionalInformationType();
    additionalInformationType.getTextualInformationOrOtherInformation().add(multiLangStringType);

    otpt.setAdditionalInformation(additionalInformationType);
    return otpt;
  }

  private static void setElementOtherTSLPointer(
      final TrustStatusListType tsl, final OtherTSLPointersType otpt) {
    tsl.getSchemeInformation().setPointersToOtherTSL(otpt);
  }

  private static XMLGregorianCalendar getXmlGregorianCalendar(final ZonedDateTime zdt)
      throws DatatypeConfigurationException {
    final XMLGregorianCalendar xmlCal =
        DatatypeFactory.newInstance().newXMLGregorianCalendar(GregorianCalendar.from(zdt));
    xmlCal.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
    return xmlCal;
  }
}
