/* Copyright (c) 2015, FIRST.ORG, INC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* This JavaScript is a modified version of the original cvsscalc30.js from FIRST
 * It was modified to calculate CVSS V2 instead of CVSS V3.
 *
 * Use CVSS.calculateCVSSFromMetrics if you wish to pass metric values as individual parameters.
 * Use CVSS.calculateCVSSFromVector if you wish to pass metric values as a single Vector String.
 *
 * Changelog
 *
 * 2017-10-06  Maxime Nadeau  Changed the file to calculate CVSS V2 instead of CVSS V3.
 *
 *
 * 2015-08-04  Darius Wiles   Added CVSS.generateXMLFromMetrics and CVSS.generateXMLFromVector functions to return
 *                            XML string representations of: a set of metric values; or a Vector String respectively.
 *                            Moved all constants and functions to an object named "CVSS" to
 *                            reduce the chance of conflicts in global variables when this file is combined with
 *                            other JavaScript code. This will break all existing code that uses this file until
 *                            the string "CVSS." is prepended to all references. The "Exploitability" metric has been
 *                            renamed "Exploit Code Maturity" in the specification, so the same change has been made
 *                            in the code in this file.
 *
 * 2015-04-24  Darius Wiles   Environmental formula modified to eliminate undesirable behavior caused by subtle
 *                            differences in rounding between Temporal and Environmental formulas that often
 *                            caused the latter to be 0.1 lower than than the former when all Environmental
 *                            metrics are "Not defined". Also added a RoundUp1 function to simplify formulas.
 *
 * 2015-04-09  Darius Wiles   Added calculateCVSSFromVector function, license information, cleaned up code and improved
 *                            comments.
 *
 * 2014-12-12  Darius Wiles   Initial release for CVSS 3.0 Preview 2.
 */

// Constants used in the formula. They are not declared as "const" to avoid problems in older browsers.

var CVSS = {};

CVSS.CVSSVersionIdentifier = "CVSS:2.0";
CVSS.impactCoefficient = 10.41;
CVSS.exploitabilityCoefficient = 20.;

// A regular expression to validate that a CVSS 2.0 vector string is well formed. It checks metrics and metric
// values. It does not check that a metric is specified more than once and it does not check that all base
// metrics are present. These checks need to be performed separately.
CVSS.vectorStringRegex_20 = /^CVSS:2\.0\/((AV:[NAL]|AC:[HML]|AU:[MSN]|[CIA]:[NPC]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|CDP:([XNLH]|LM|MH)|TD:[XNLMH]|[CIA]R:[XLMH])\/)*(AV:[NAL]|AC:[HML]|AU:[MSN]|[CIA]:[NPC]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|CDP:([XNLH]|LM|MH)|TD:[XNLMH]|[CIA]R:[XLMH])$/;


// Associative arrays mapping each metric value to the constant defined in the CVSS scoring formula in the CVSS v2.0
// specification.

CVSS.Weight = {
  AV:   { N: 1.,    A: 0.646,  L: 0.395},
  AC:   { H: 0.35,  M: 0.61,   L: 0.71},
  AU:   { M: 0.45,  S: 0.56,   N: 0.704},
  CIA:  { N: 0.,    P: 0.275,  C: 0.660},                   // C, I and A have the same weights

  E:    { X: 1.,     U: 0.85,   P: 0.90,  F: 0.95,  H: 1.},
  RL:   { X: 1.,     O: 0.87,   T: 0.90,  W: 0.95,  U: 1.},
  RC:   { X: 1.,     U: 0.90,   R: 0.95,  C: 1.},

  CDP:  { X: 0.,     N: 0.,     L: 0.1,   LM: 0.3,  MH: 0.4,  H: 0.5 },
  TD:   { X: 1.,     N: 0.,     L: 0.25,  M: 0.75,  H: 1. },

  CIAR: { X: 1.,     L: 0.5,    M: 1.,     H: 1.51}           // CR, IR and AR have the same weights
};


// Severity rating bands, as defined in the CVSS v2.0 specification.

CVSS.severityRatings  = [ { name: "Low",      bottom: 0.0, top:  3.9},
                          { name: "Medium",   bottom: 4.0, top:  6.9},
                          { name: "High",     bottom: 7.0, top:  10.0} ];




/* ** CVSS.calculateCVSSFromMetrics **
 *
 * Takes Base, Temporal and Environmental metric values as individual parameters. Their values are in the short format
 * defined in the CVSS v2.0 standard definition of the Vector String. For example, the AttackComplexity parameter
 * should be either "H" or "L".
 *
 * Returns Base, Temporal and Environmental scores, severity ratings, and an overall Vector String. All Base metrics
 * are required to generate this output. All Temporal and Environmental metric values are optional. Any that are not
 * passed default to "X" ("Not Defined").
 *
 * The output is an object which always has a property named "success".
 *
 * If no errors are encountered, success is Boolean "true", and the following other properties are defined containing
 * scores, severities and a vector string:
 *   baseMetricScore, baseSeverity,
 *   temporalMetricScore, temporalSeverity,
 *   environmentalMetricScore, environmentalSeverity,
 *   vectorString
 *
 * If errors are encountered, success is Boolean "false", and the following other properties are defined:
 *   errorType - a string indicating the error. Either:
 *                 "MissingBaseMetric", if at least one Base metric has not been defined; or
 *                 "UnknownMetricValue", if at least one metric value is invalid.
 *   errorMetrics - an array of strings representing the metrics at fault. The strings are abbreviated versions of the
 *                  metrics, as defined in the CVSS v2.0 standard definition of the Vector String.
 */
CVSS.calculateCVSSFromMetrics = function (
  AttackVector, AttackComplexity, Authentication, Confidentiality, Integrity, Availability,
  Exploitability, RemediationLevel, ReportConfidence,
  IntegrityRequirement, ConfidentialityRequirement, AvailabilityRequirement,
  CollateralDamagePotential, TargetDistribution) {

  // If input validation fails, this array is populated with strings indicating which metrics failed validation.
  var badMetrics = [];

  // ENSURE ALL BASE METRICS ARE DEFINED
  //
  // We need values for all Base Score metrics to calculate scores.
  // If any Base Score parameters are undefined, create an array of missing metrics and return it with an error.

  if (typeof AttackVector       === "undefined" || AttackVector       === "") { badMetrics.push("AV"); }
  if (typeof AttackComplexity   === "undefined" || AttackComplexity   === "") { badMetrics.push("AC"); }
  if (typeof Authentication     === "undefined" || Authentication     === "") { badMetrics.push("AU"); }
  if (typeof Confidentiality    === "undefined" || Confidentiality    === "") { badMetrics.push("C");  }
  if (typeof Integrity          === "undefined" || Integrity          === "") { badMetrics.push("I");  }
  if (typeof Availability       === "undefined" || Availability       === "") { badMetrics.push("A");  }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "MissingBaseMetric", errorMetrics: badMetrics };
  }


  // STORE THE METRIC VALUES THAT WERE PASSED AS PARAMETERS
  //
  // Temporal and Environmental metrics are optional, so set them to "X" ("Not Defined") if no value was passed.

  var AV = AttackVector;
  var AC = AttackComplexity;
  var AU = Authentication;
  var C  = Confidentiality;
  var I  = Integrity;
  var A  = Availability;

  var E =   Exploitability      || "X";
  var RL =  RemediationLevel    || "X";
  var RC =  ReportConfidence    || "X";

  var CDP = CollateralDamagePotential  || "X";
  var TD = TargetDistribution          || "X";

  var CR =  ConfidentialityRequirement || "X";
  var IR =  IntegrityRequirement       || "X";
  var AR =  AvailabilityRequirement    || "X";

  // CHECK VALIDITY OF METRIC VALUES
  //
  // Use the Weight object to ensure that, for every metric, the metric value passed is valid.
  // If any invalid values are found, create an array of their metrics and return it with an error.
  //
  // The Privileges Required (PR) weight depends on Scope, but when checking the validity of PR we must not assume
  // that the given value for Scope is valid. We therefore always look at the weights for Unchanged Scope when
  // performing this check. The same applies for validation of Modified Privileges Required (MPR).
  //
  // The Weights object does not contain "X" ("Not Defined") values for Environmental metrics because we replace them
  // with their Base metric equivalents later in the function. For example, an MAV of "X" will be replaced with the
  // value given for AV. We therefore need to explicitly allow a value of "X" for Environmental metrics.

  if (!CVSS.Weight.AV.hasOwnProperty(AV))   { badMetrics.push("AV"); }
  if (!CVSS.Weight.AC.hasOwnProperty(AC))   { badMetrics.push("AC"); }
  if (!CVSS.Weight.AU.hasOwnProperty(AU))   { badMetrics.push("AU"); }
  if (!CVSS.Weight.CIA.hasOwnProperty(C))   { badMetrics.push("C"); }
  if (!CVSS.Weight.CIA.hasOwnProperty(I))   { badMetrics.push("I"); }
  if (!CVSS.Weight.CIA.hasOwnProperty(A))   { badMetrics.push("A"); }

  if (!CVSS.Weight.E.hasOwnProperty(E))     { badMetrics.push("E"); }
  if (!CVSS.Weight.RL.hasOwnProperty(RL))   { badMetrics.push("RL"); }
  if (!CVSS.Weight.RC.hasOwnProperty(RC))   { badMetrics.push("RC"); }

  if (!(CDP === "X"  || CVSS.Weight.CDP.hasOwnProperty(CDP))) { badMetrics.push("CDP"); }
  if (!(TD  === "X"  || CVSS.Weight.TD.hasOwnProperty(MAC)))  { badMetrics.push("TD"); }

  if (!(CR  === "X" || CVSS.Weight.CIAR.hasOwnProperty(CR)))  { badMetrics.push("CR"); }
  if (!(IR  === "X" || CVSS.Weight.CIAR.hasOwnProperty(IR)))  { badMetrics.push("IR"); }
  if (!(AR  === "X" || CVSS.Weight.CIAR.hasOwnProperty(AR)))  { badMetrics.push("AR"); }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "UnknownMetricValue", errorMetrics: badMetrics };
  }



  // GATHER WEIGHTS FOR ALL METRICS

  var metricWeightAV  = CVSS.Weight.AV    [AV];
  var metricWeightAC  = CVSS.Weight.AC    [AC];
  var metricWeightAU  = CVSS.Weight.AU    [AU];
  var metricWeightC   = CVSS.Weight.CIA   [C];
  var metricWeightI   = CVSS.Weight.CIA   [I];
  var metricWeightA   = CVSS.Weight.CIA   [A];

  var metricWeightE   = CVSS.Weight.E     [E];
  var metricWeightRL  = CVSS.Weight.RL    [RL];
  var metricWeightRC  = CVSS.Weight.RC    [RC];

  var metricWeightCDP = CVSS.Weight.CDP   [CDP];
  var metricWeightTD  = CVSS.Weight.TD    [TD];

  // For metrics that are modified versions of Base Score metrics, e.g. Modified Attack Vector, use the value of
  // the Base Score metric if the modified version value is "X" ("Not Defined").
  var metricWeightCR  = CVSS.Weight.CIAR  [CR];
  var metricWeightIR  = CVSS.Weight.CIAR  [IR];
  var metricWeightAR  = CVSS.Weight.CIAR  [AR];


  // CALCULATE THE CVSS BASE SCORE
  var baseScore;
  var impactSubScore = CVSS.impactCoefficient * (1 - (1 - metricWeightC) * (1 - metricWeightI) * (1 - metricWeightA));
  var exploitabalitySubScore = CVSS.exploitabilityCoefficient * metricWeightAC * metricWeightAV * metricWeightAU;

  var impactF = 0.;
  if (impactSubScore != 0) {
    impactF = 1.176;
  }

  baseScore = CVSS.roundToOneDecimal((0.6 * impactSubScore + 0.4 * exploitabalitySubScore - 1.5) * impactF)

  // CALCULATE THE CVSS TEMPORAL SCORE
  var temporalScore = CVSS.roundToOneDecimal(baseScore * metricWeightE * metricWeightRL * metricWeightRC)

  // CALCULATE THE CVSS ENVIRONMENTAL SCORE
  var envScore;
  var envModifiedImpactSubScore = Math.min(CVSS.impactCoefficient * (1 - (1 - metricWeightC * metricWeightCR) * (1 - metricWeightI * metricWeightIR) * (1 - metricWeightA * metricWeightAR)), 10);

  var modifiedImpactF = 0.;
  if (envModifiedImpactSubScore != 0) {
      modifiedImpactF = 1.176
  }

  var modifiedBase = CVSS.roundToOneDecimal((0.6 * envModifiedImpactSubScore + 0.4 * exploitabalitySubScore - 1.5) * modifiedImpactF)
  var adjustedTemporal = modifiedBase * metricWeightE * metricWeightRL * metricWeightRC;
  envScore = CVSS.roundToOneDecimal((adjustedTemporal + (10. - adjustedTemporal) * metricWeightCDP) * metricWeightTD)


  // CONSTRUCT THE VECTOR STRING

  var vectorString =
    CVSS.CVSSVersionIdentifier +
    "/AV:" + AV +
    "/AC:" + AC +
    "/AU:" + AU +
    "/C:"  + C +
    "/I:"  + I +
    "/A:"  + A;

  if (E  !== "X")  {vectorString = vectorString + "/E:" + E;}
  if (RL !== "X")  {vectorString = vectorString + "/RL:" + RL;}
  if (RC !== "X")  {vectorString = vectorString + "/RC:" + RC;}

  if (CDP !== "X") {vectorString = vectorString + "/CDP:" + CDP;}
  if (TD !== "X") {vectorString = vectorString + "/TD:" + TD;}

  if (CR  !== "X") {vectorString = vectorString + "/CR:" + CR;}
  if (IR  !== "X") {vectorString = vectorString + "/IR:"  + IR;}
  if (AR  !== "X") {vectorString = vectorString + "/AR:"  + AR;}


  // Return an object containing the scores for all three metric groups, and an overall vector string.

  return {
    success: true,
    baseMetricScore: baseScore.toFixed(1),
    baseSeverity: CVSS.severityRating( baseScore.toFixed(1) ),

    temporalMetricScore: temporalScore.toFixed(1),
    temporalSeverity: CVSS.severityRating( temporalScore.toFixed(1) ),

    environmentalMetricScore: envScore.toFixed(1),
    environmentalSeverity: CVSS.severityRating( envScore.toFixed(1) ),

    vectorString: vectorString
  };
};




/* ** CVSS.calculateCVSSFromVector **
 *
 * Takes Base, Temporal and Environmental metric values as a single string in the Vector String format defined
 * in the CVSS v2.0 standard definition of the Vector String.
 *
 * Returns Base, Temporal and Environmental scores, severity ratings, and an overall Vector String. All Base metrics
 * are required to generate this output. All Temporal and Environmental metric values are optional. Any that are not
 * passed default to "X" ("Not Defined").
 *
 * See the comment for the CVSS.calculateCVSSFromMetrics function for details on the function output. In addition to
 * the error conditions listed for that function, this function can also return:
 *   "MalformedVectorString", if the Vector String passed is does not conform to the format in the standard; or
 *   "MultipleDefinitionsOfMetric", if the Vector String is well formed but defines the same metric (or metrics),
 *                                  more than once.
 */
CVSS.calculateCVSSFromVector = function ( vectorString ) {

  var metricValues = {
    AV:  undefined, AC:  undefined, AU:  undefined,
    C:   undefined, I:   undefined, A:   undefined,
    E:   undefined, RL:  undefined, RC:  undefined,
    CR:  undefined, IR:  undefined, AR:  undefined,
    CDP: undefined, TD: undefined
  };

  // If input validation fails, this array is populated with strings indicating which metrics failed validation.
  var badMetrics = [];

  if (!CVSS.vectorStringRegex_20.test(vectorString)) {
    return { success: false, errorType: "MalformedVectorString" };
  }

  var metricNameValue = vectorString.substring(CVSS.CVSSVersionIdentifier.length).split("/");

  for (var i in metricNameValue) {
    if (metricNameValue.hasOwnProperty(i)) {

      var singleMetric = metricNameValue[i].split(":");

      if (typeof metricValues[singleMetric[0]] === "undefined") {
        metricValues[singleMetric[0]] = singleMetric[1];
      } else {
        badMetrics.push(singleMetric[0]);
      }
    }
  }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "MultipleDefinitionsOfMetric", errorMetrics: badMetrics };
  }

  return CVSS.calculateCVSSFromMetrics (
    metricValues.AV,  metricValues.AC,  metricValues.AU,
    metricValues.C,   metricValues.I,   metricValues.A,
    metricValues.E,   metricValues.RL,  metricValues.RC,
    metricValues.CR,  metricValues.IR,  metricValues.AR,
    metricValues.CDP, metricValues.TD);
};




/* ** CVSS.roundUp1 **
 *
 * Rounds up the number passed as a parameter to 1 decimal place and returns the result.
 *
 * Standard JavaScript errors thrown when arithmetic operations are performed on non-numbers will be returned if the
 * given input is not a number.
 */
CVSS.roundToOneDecimal = function (d) {
  return Math.round(d * 10) / 10;
};




/* ** CVSS.severityRating **
 *
 * Given a CVSS score, returns the name of the severity rating as defined in the CVSS standard.
 * The input needs to be a number between 0.0 to 10.0, to one decimal place of precision.
 *
 * The following error values may be returned instead of a severity rating name:
 *   NaN (JavaScript "Not a Number") - if the input is not a number.
 *   undefined - if the input is a number that is not within the range of any defined severity rating.
 */
CVSS.severityRating = function (score) {
  var severityRatingLength = CVSS.severityRatings.length;

  var validatedScore = Number(score);

  if (isNaN(validatedScore)) {
    return validatedScore;
  }

  for (var i = 0; i < severityRatingLength; i++) {
    if (score >= CVSS.severityRatings[i].bottom && score <= CVSS.severityRatings[i].top) {
      return CVSS.severityRatings[i].name;
    }
  }

  return undefined;
};
