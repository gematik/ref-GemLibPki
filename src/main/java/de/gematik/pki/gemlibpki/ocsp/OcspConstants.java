/*
 * Copyright 2025, gematik GmbH
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
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.ocsp;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class OcspConstants {

  public static final int OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS = 37_500;
  public static final int OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS = 37_500;
  public static final int OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS = 37_500;

  public static final String MEDIA_TYPE_APPLICATION_OCSP_REQUEST = "application/ocsp-request";
  public static final String MEDIA_TYPE_APPLICATION_OCSP_RESPONSE = "application/ocsp-response";
  public static final int DEFAULT_OCSP_TIMEOUT_SECONDS = 10;
}
