import { CvssV30MetricCodeMap, CvssV31MetricCodeMap } from "./cvss-base.js";
/**
 * CVSS Version
 */
export var CvssVersion;
(function (CvssVersion) {
    CvssVersion["V30"] = "3.0";
    CvssVersion["V31"] = "3.1";
})(CvssVersion || (CvssVersion = {}));
/**
 * 获取严重性等级
 * @param score 评分
 * @returns 严重性等级
 */
export function getSeverityRating(score) {
    if (score < 0.0 || score > 10.0) {
        throw new Error("Invalid CVSS score");
    }
    if (score >= 9.0) {
        return "Critical";
    }
    else if (score >= 7.0) {
        return "High";
    }
    else if (score >= 4.0) {
        return "Medium";
    }
    else if (score >= 0.1) {
        return "Low";
    }
    else {
        return "None";
    }
}
/**
 * 解析CVSS向量字符串
 * @param {string} vectorString CVSS向量字符串，示例：CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N
 * @returns {CvssQualitativeMetricScore} 指标评分对象
 */
export function parseVectorString(vectorString) {
    const metricScore = {
        version: "",
        vectorString: "",
        baseScore: 0,
        baseSeverity: "",
        temporalScore: 0,
        temporalSeverity: "",
        environmentalScore: 0,
        environmentalSeverity: "",
        isScopeChanged: false,
        isModifiedScopeChanged: false,
        qualitativeMetricValues: [],
    };
    const parts = vectorString.split("/");
    // 版本
    metricScore.version = parts[0].replace("CVSS:", "");
    if (metricScore.version !== CvssVersion.V30 && metricScore.version !== CvssVersion.V31) {
        throw new Error("Invalid CVSS version");
    }
    // 指标
    for (let i = 1; i < parts.length; i++) {
        const [key, value] = parts[i].split(":");
        if (!key || !value) {
            throw new Error("Invalid CVSS metric format");
        }
        if (key === "S" && value === "C") {
            metricScore.isScopeChanged = true;
        }
        if (key === "MS" && value === "C") {
            metricScore.isModifiedScopeChanged = true;
        }
        metricScore.qualitativeMetricValues.push({
            metricName: "",
            metricCode: key,
            metricValue: value,
            metricScore: 0,
        });
    }
    metricScore.vectorString = vectorString;
    return metricScore;
}
/**
 * 获取CVSS指标对象
 * @param version CVSS版本
 * @param metricCode 指标代码
 * @returns 指标对象
 */
export function findCvssMetric(version, metricCode) {
    switch (version) {
        case CvssVersion.V30:
            return CvssV30MetricCodeMap[metricCode];
        case CvssVersion.V31:
            return CvssV31MetricCodeMap[metricCode];
        default:
            throw new Error("Invalid CVSS version");
    }
}
/**
 * 解决定性指标名称和评分
 * @param metricScore 指标评分对象
 * @returns 指标评分对象
 */
export function resolveQualitativeMetricNameAndValue(metricScore) {
    metricScore.qualitativeMetricValues.forEach((metric) => {
        const cvssMetric = findCvssMetric(metricScore.version, metric.metricCode);
        // 指标名称
        metric.metricName = cvssMetric.name;
        // 指标值
        const cvssMetricValue = cvssMetric.values.find((v) => v.code === metric.metricValue);
        if (!cvssMetricValue) {
            throw new Error(`Invalid CVSS metric value ${metric.metricValue} for metric ${metric.metricCode}`);
        }
        if (metric.metricCode === "PR" && cvssMetricValue.code !== "N") {
            metric.metricScore = cvssMetricValue.value(metricScore.isScopeChanged);
        }
        else if (metric.metricCode === "MPR" && cvssMetricValue.code !== "N") {
            metric.metricScore = cvssMetricValue.value(metricScore.isModifiedScopeChanged);
        }
        else {
            metric.metricScore = cvssMetricValue.value();
        }
    });
    return metricScore;
}
/**
 * 计算基本评分
 * @param metricScore 指标评分对象
 * @returns 指标评分对象
 */
export function calculateBaseScore(metricScore) {
    // 解析指标值
    const attackVector = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "AV")?.metricScore;
    const attackComplexity = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "AC")?.metricScore;
    const privilegesRequired = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "PR")?.metricScore;
    const userInteraction = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "UI")?.metricScore;
    const scope = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "S")?.metricScore;
    const confidentiality = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "C")?.metricScore;
    const integrity = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "I")?.metricScore;
    const availability = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "A")?.metricScore;
    // 检查是否有必要的指标缺失
    if (attackVector === undefined
        || attackComplexity === undefined
        || privilegesRequired === undefined
        || userInteraction === undefined
        || scope === undefined
        || confidentiality === undefined
        || integrity === undefined
        || availability === undefined) {
        throw new Error("Missing required base metrics");
    }
    // 计算利用子评分
    const exploitabilityScore = 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction;
    // 计算ISC/ISS
    const impactScoreBase = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability));
    // 计算影响子评分
    let impactScore;
    if (metricScore.isScopeChanged) {
        impactScore = 7.52 * (impactScoreBase - 0.029) - 3.25 * (impactScoreBase - 0.02) ** 15;
    }
    else {
        impactScore = 6.42 * impactScoreBase;
    }
    // 计算基本评分
    let baseScore;
    if (impactScore <= 0) {
        baseScore = 0.0;
    }
    else if (metricScore.isScopeChanged) {
        baseScore = Math.min(1.08 * (exploitabilityScore + impactScore), 10.0);
    }
    else {
        baseScore = Math.min((exploitabilityScore + impactScore), 10.0);
    }
    // 向上取整到一位小数
    metricScore.baseScore = Math.ceil(baseScore * 10) / 10;
    // 计算严重性等级
    metricScore.baseSeverity = getSeverityRating(metricScore.baseScore);
    return metricScore;
}
/**
 * 计算临时评分
 * @param metricScore 指标评分对象
 * @returns 指标评分对象
 */
export function calculateTemporalScore(metricScore) {
    if (metricScore.baseScore === 0.0) {
        metricScore.temporalScore = 0.0;
        return metricScore;
    }
    // 解析临时指标值
    const exploitCodeMaturity = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "E")?.metricScore || 1;
    const remediationLevel = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "RL")?.metricScore || 1;
    const reportConfidence = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "RC")?.metricScore || 1;
    // 计算临时评分
    const temporalScore = metricScore.baseScore * exploitCodeMaturity * remediationLevel * reportConfidence;
    // 向上取整到一位小数
    metricScore.temporalScore = Math.ceil(temporalScore * 10) / 10;
    // 计算严重性等级
    metricScore.temporalSeverity = getSeverityRating(metricScore.temporalScore);
    return metricScore;
}
/**
 * 计算环境评分
 * @param metricScore 指标评分对象
 * @returns 指标评分对象
 */
export function calculateEnvironmentalScore(metricScore) {
    if (metricScore.baseScore === 0.0) {
        metricScore.environmentalScore = 0.0;
        return metricScore;
    }
    // 解析环境指标值
    const modifiedAttackVector = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "MAV")?.metricScore || metricScore.qualitativeMetricValues.find((m) => m.metricCode === "AV")?.metricScore;
    const modifiedAttackComplexity = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "MAC")?.metricScore || metricScore.qualitativeMetricValues.find((m) => m.metricCode === "AC")?.metricScore;
    const modifiedPrivilegesRequired = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "MPR")?.metricScore || metricScore.qualitativeMetricValues.find((m) => m.metricCode === "PR")?.metricScore;
    const modifiedUserInteraction = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "MU")?.metricScore || metricScore.qualitativeMetricValues.find((m) => m.metricCode === "UI")?.metricScore;
    const modifiedScope = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "MS")?.metricScore || metricScore.qualitativeMetricValues.find((m) => m.metricCode === "S")?.metricScore;
    const modifiedConfidentiality = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "MC")?.metricScore || metricScore.qualitativeMetricValues.find((m) => m.metricCode === "C")?.metricScore;
    const modifiedIntegrity = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "MI")?.metricScore || metricScore.qualitativeMetricValues.find((m) => m.metricCode === "I")?.metricScore;
    const modifiedAvailability = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "MA")?.metricScore || metricScore.qualitativeMetricValues.find((m) => m.metricCode === "A")?.metricScore;
    // 检查是否有必要的指标缺失
    if (modifiedAttackVector === undefined
        || modifiedAttackComplexity === undefined
        || modifiedPrivilegesRequired === undefined
        || modifiedUserInteraction === undefined
        || modifiedScope === undefined
        || modifiedConfidentiality === undefined
        || modifiedIntegrity === undefined
        || modifiedAvailability === undefined) {
        throw new Error("Missing required environmental metrics");
    }
    // 解析环境指标值
    const confidentialityRequirement = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "CR")?.metricScore || 1;
    const integrityRequirement = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "IR")?.metricScore || 1;
    const availabilityRequirement = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "AR")?.metricScore || 1;
    // 解析临时指标值
    const exploitCodeMaturity = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "E")?.metricScore || 1;
    const remediationLevel = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "RL")?.metricScore || 1;
    const reportConfidence = metricScore.qualitativeMetricValues.find((m) => m.metricCode === "RC")?.metricScore || 1;
    // 计算修改后的利用子评分
    const modifiedExploitabilityScore = 8.22 * modifiedAttackVector * modifiedAttackComplexity * modifiedPrivilegesRequired * modifiedUserInteraction;
    // 计算修改后的MISC/MISS
    const modifiedImpactScoreBase = Math.min(1 - ((1 - modifiedConfidentiality * confidentialityRequirement) * (1 - modifiedIntegrity * integrityRequirement) * (1 - modifiedAvailability * availabilityRequirement)), 0.915);
    // 计算修改后的影响子评分
    let modifiedImpactScore;
    if (metricScore.isModifiedScopeChanged) {
        if (metricScore.version === CvssVersion.V30) {
            // v3.0
            modifiedImpactScore = 7.52 * (modifiedImpactScoreBase - 0.029) - 3.25 * (modifiedImpactScoreBase - 0.02) ** 15;
        }
        else {
            // v3.1
            modifiedImpactScore = 7.52 * (modifiedImpactScoreBase - 0.029) - 3.25 * (modifiedImpactScoreBase * 0.9731 - 0.02) ** 13;
        }
    }
    else {
        modifiedImpactScore = 6.42 * modifiedImpactScoreBase;
    }
    // 计算环境评分
    let environmentalScore;
    if (modifiedImpactScore <= 0) {
        environmentalScore = 0.0;
    }
    else if (metricScore.isModifiedScopeChanged) {
        environmentalScore = Math.min(1.08 * (modifiedExploitabilityScore + modifiedImpactScore), 10.0);
        environmentalScore = Math.ceil(environmentalScore * 10) / 10;
        environmentalScore = environmentalScore * exploitCodeMaturity * remediationLevel * reportConfidence;
    }
    else {
        environmentalScore = Math.min(modifiedExploitabilityScore + modifiedImpactScore, 10.0);
        environmentalScore = Math.ceil(environmentalScore * 10) / 10;
        environmentalScore = environmentalScore * exploitCodeMaturity * remediationLevel * reportConfidence;
    }
    // 向上取整到一位小数
    metricScore.environmentalScore = Math.ceil(environmentalScore * 10) / 10;
    // 计算严重性等级
    metricScore.environmentalSeverity = getSeverityRating(metricScore.environmentalScore);
    return metricScore;
}
/**
 * 计算CVSS评分
 * @param vectorString CVSS向量字符串
 * @returns 评分结果
 */
export function calculateCvssScore(vectorString) {
    // 解析向量字符串
    let metricScore = parseVectorString(vectorString);
    // 解析定性指标名称和值
    metricScore = resolveQualitativeMetricNameAndValue(metricScore);
    // 计算基本评分
    metricScore = calculateBaseScore(metricScore);
    // 计算临时评分
    metricScore = calculateTemporalScore(metricScore);
    // 计算环境评分
    metricScore = calculateEnvironmentalScore(metricScore);
    return metricScore;
}
