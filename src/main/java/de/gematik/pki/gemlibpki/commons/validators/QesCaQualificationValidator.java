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

package de.gematik.pki.gemlibpki.commons.validators;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.tsl.TslConstants;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceStatusHistoryEntry;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceSubset;
import java.time.ZonedDateTime;
import java.util.Comparator;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/** Validator for qualification and status of a QES CA service from the BNetzA-VL. */
@RequiredArgsConstructor
public class QesCaQualificationValidator {

  @NonNull private final String productType;
  @NonNull private final TspServiceSubset qesCaTspServiceSubset;

  /**
   * Validate if the QES CA service is qualified and already valid at the given reference date.
   *
   * @param referenceDate point in time for the status evaluation
   * @throws GemPkiException if the QES CA service is not qualified at the reference date
   */
  public void validate(@NonNull final ZonedDateTime referenceDate) throws GemPkiException {
    final ZonedDateTime statusStartingTime = qesCaTspServiceSubset.getStatusStartingTime();
    final String serviceStatus = qesCaTspServiceSubset.getServiceStatus();

    if (statusStartingTime != null
        && TslConstants.SVCSTATUS_GRANTED.equals(serviceStatus)
        && !statusStartingTime.isAfter(referenceDate)) {
      return;
    }

    if (isHistoricallyQualifiedWhileWithdrawn(referenceDate, serviceStatus, statusStartingTime)) {
      return;
    }

    throw new GemPkiException(productType, ErrorCode.SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED);
  }

  private boolean isHistoricallyQualifiedWhileWithdrawn(
      final ZonedDateTime referenceDate,
      final String serviceStatus,
      final ZonedDateTime statusStartingTime) {
    if (!TslConstants.SVCSTATUS_WITHDRAWN.equals(serviceStatus)
        || statusStartingTime == null
        || !statusStartingTime.isAfter(referenceDate)) {
      return false;
    }

    return qesCaTspServiceSubset.getServiceStatusHistory().stream()
        .filter(this::isProcessableHistoryEntry)
        .filter(historyEntry -> !historyEntry.statusStartingTime().isAfter(referenceDate))
        .max(Comparator.comparing(TspServiceStatusHistoryEntry::statusStartingTime))
        .map(historyEntry -> TslConstants.SVCSTATUS_GRANTED.equals(historyEntry.serviceStatus()))
        .orElse(false);
  }

  private boolean isProcessableHistoryEntry(final TspServiceStatusHistoryEntry historyEntry) {
    return historyEntry != null
        && historyEntry.serviceStatus() != null
        && historyEntry.statusStartingTime() != null;
  }
}
