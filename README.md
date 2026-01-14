# CVSS

## CVSS Specification Document

- [CVSS V3.0 Specification Document](https://www.first.org/cvss/v3.0/specification-document)
- [CVSS V3.1 Specification Document](https://www.first.org/cvss/v3.1/specification-document)

## Installation

```bash
npm install @ppbong/cvss
```

## Usage Example

```javascript
import { calculateCvssScore } from '@ppbong/cvss';

const printCvssScore = (cvssScore) => {
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
}

const cvssV30Score = calculateCvssScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
const cvssV31Score = calculateCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

printCvssScore(cvssV30Score);
printCvssScore(cvssV31Score);
```
