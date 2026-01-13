import { calculateCvssScore } from '../lib/index.js';

const cvssScore = calculateCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

console.log("CVSS Version: " + cvssScore.version);
console.log("CVSS Base Score: " + cvssScore.baseScore);
console.log("CVSS Base Severity: " + cvssScore.baseSeverity);
console.log("CVSS Temporal Score: " + cvssScore.temporalScore);
console.log("CVSS Temporal Severity: " + cvssScore.temporalSeverity);
console.log("CVSS Environmental Score: " + cvssScore.environmentalScore);
console.log("CVSS Environmental Severity: " + cvssScore.environmentalSeverity);
console.log("CVSS Scope is Changed: " + cvssScore.isScopeChanged);
console.log("CVSS Modified Scope is Changed: " + cvssScore.isModifiedScopeChanged);
console.log("CVSS Metric: ");
cvssScore.qualitativeMetricValues.forEach((m) => {
    console.log(m.metricName + " : " + m.metricCode + " : " + m.metricValue + " : " + m.metricScore);
});
