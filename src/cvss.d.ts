/**
 * CVSS Metric Value
 * @description 指标值
 * @property {string} name - 指标名称
 * @property {string} code - 指标代码
 * @property {string} label - 指标标签
 * @property {number} value - 指标值
 */
export declare interface CvssMetricValue {
  name: string;
  code: string;
  label: string;
  value(isScopeOrModifiedScopeChanged?: boolean): number;
}

/**
 * CVSS Metric
 * @description 指标
 * @property {string} name - 指标名称
 * @property {string} code - 指标代码
 * @property {string} label - 指标标签
 * @property {MetricValue[]} values - 指标值
 */
export declare interface CvssMetric {
  name: string;
  code: string;
  label: string;
  values: CvssMetricValue[];
}

/**
 * CVSS V3.0 Exploitability Metrics
 * @description 利用指标
 * @property {CvssMetric} attackVector - 攻击向量
 * @property {CvssMetric} attackComplexity - 攻击复杂度
 * @property {CvssMetric} privilegesRequired - 权限要求
 * @property {CvssMetric} userInteraction - 用户交互
 */
export declare interface CvssV30ExploitabilityMetrics {
  attackVector: CvssMetric;
  attackComplexity: CvssMetric;
  privilegesRequired: CvssMetric;
  userInteraction: CvssMetric;
}

/**
 * CVSS V3.0 Scope Metrics
 * @description 范围指标
 * @property {CvssMetric} scope - 范围
 */
export declare interface CvssV30ScopeMetrics {
  scope: CvssMetric;
}

/**
 * CVSS V3.0 Impact Metrics
 * @description 影响指标
 * @property {CvssMetric} confidentialityImpact - 机密性影响
 * @property {CvssMetric} integrityImpact - 完整性影响
 * @property {CvssMetric} availabilityImpact - 可用性影响
 */
export declare interface CvssV30ImpactMetrics {
  confidentialityImpact: CvssMetric;
  integrityImpact: CvssMetric;
  availabilityImpact: CvssMetric;
}


/**
 * CVSS V3.0 Base Metrics
 * 
 * @description 基本指标
 * @extends CvssV30ExploitabilityMetrics
 * @extends CvssV30ScopeMetrics
 * @extends CvssV30ImpactMetrics
 */
export declare interface CvssV30BaseMetrics extends CvssV30ExploitabilityMetrics, CvssV30ScopeMetrics, CvssV30ImpactMetrics {
}

/**
 * CVSS V3.0 Temporal Metrics
 * 
 * @description 临时指标
 * @property {CvssMetric} exploitCodeMaturity - 利用代码成熟度
 * @property {CvssMetric} remediationLevel - 修复级别
 * @property {CvssMetric} reportConfidence - 报告置信度
 */
export declare interface CvssV30TemporalMetrics {
  exploitCodeMaturity: CvssMetric;
  remediationLevel: CvssMetric;
  reportConfidence: CvssMetric;
}

/**
 * CVSS V3.0 Security Requirement Metrics
 * @description 安全需求指标
 * @property {CvssMetric} confidentialityRequirement - 机密性需求
 * @property {CvssMetric} integrityRequirement - 完整性需求
 * @property {CvssMetric} availabilityRequirement - 可用性需求
 */
export declare interface CvssV30SecurityRequirementMetrics {
  confidentialityRequirement: CvssMetric;
  integrityRequirement: CvssMetric;
  availabilityRequirement: CvssMetric;
}

/**
 * CVSS V3.0 Modified Base Metrics
 * @description 修改后的基本指标
 * @property {CvssMetric} modifiedAttackVector - 修改后的攻击向量
 * @property {CvssMetric} modifiedAttackComplexity - 修改后的攻击复杂度
 * @property {CvssMetric} modifiedPrivilegesRequired - 修改后的权限要求
 * @property {CvssMetric} modifiedUserInteraction - 修改后的用户交互
 * @property {CvssMetric} modifiedScope - 修改后的范围
 * @property {CvssMetric} modifiedConfidentialityImpact - 修改后的机密性影响
 * @property {CvssMetric} modifiedIntegrityImpact - 修改后的完整性影响
 * @property {CvssMetric} modifiedAvailabilityImpact - 修改后的可用性影响
 */
export declare interface CvssV30ModifiedBaseMetrics {
  modifiedAttackVector: CvssMetric;
  modifiedAttackComplexity: CvssMetric;
  modifiedPrivilegesRequired: CvssMetric;
  modifiedUserInteraction: CvssMetric;
  modifiedScope: CvssMetric;
  modifiedConfidentialityImpact: CvssMetric;
  modifiedIntegrityImpact: CvssMetric;
  modifiedAvailabilityImpact: CvssMetric;
}

/**
 * CVSS V3.0 Environmental Metrics
 * @description 环境指标
 * @extends CvssV30SecurityRequirementMetrics
 * @extends CvssV30ModifiedBaseMetrics
 */
export declare interface CvssV30EnvironmentalMetrics extends CvssV30SecurityRequirementMetrics, CvssV30ModifiedBaseMetrics {
}

/**
 * CVSS V3.1 Base Metrics
 * @description 基本指标
 * @extends CvssV30BaseMetrics
 * @property {CvssMetric} confidentiality - 机密性
 * @property {CvssMetric} integrity - 完整性
 * @property {CvssMetric} availability - 可用性
 */
export declare interface CvssV31BaseMetrics extends Omit<CvssV30BaseMetrics, 'confidentialityImpact' | 'integrityImpact' | 'availabilityImpact'> {
  confidentiality: CvssMetric;
  integrity: CvssMetric;
  availability: CvssMetric;
}

/**
 * CVSS V3.1 Temporal Metrics
 * @description 临时指标
 * @extends CvssV30TemporalMetrics
 */
export declare interface CvssV31TemporalMetrics extends CvssV30TemporalMetrics {
}

/**
 * CVSS V3.1 Environmental Metrics
 * @description 环境指标
 * @extends CvssV30EnvironmentalMetrics
 * @property {CvssMetric} modifiedConfidentiality - 修改后的机密性
 * @property {CvssMetric} modifiedIntegrity - 修改后的完整性
 * @property {CvssMetric} modifiedAvailability - 修改后的可用性
 */
export declare interface CvssV31EnvironmentalMetrics extends Omit<CvssV30EnvironmentalMetrics, 'modifiedConfidentialityImpact' | 'modifiedIntegrityImpact' | 'modifiedAvailabilityImpact'> {
  modifiedConfidentiality: CvssMetric;
  modifiedIntegrity: CvssMetric;
  modifiedAvailability: CvssMetric;
}

/**
 * CVSS V3.1 Qualitative Severity Rating
 * @description 定性严重性等级
 * @property {string} name - 名称
 * @property {string} label - 标签
 * @property {string} scoreScope - 分数范围
 */
export declare interface CvssQualitativeSeverityRating {
  name: string;
  label: string;
  scoreScope: string;
}

/**
 * CVSS V3.0 Qualitative Metric Value
 * @description 定性指标值
 * @property {string} metricName - 指标名称
 * @property {string} metricCode - 指标代码
 * @property {string} metricValue - 指标值
 * @property {number} metricScore - 指标分数
 */
export declare interface CvssQualitativeMetricValue {
  metricName: string;
  metricCode: string;
  metricValue: string;
  metricScore: number;
}

/**
 * CVSS V3.0 Qualitative Metric Score
 * @description 定性指标分数
 * @property {string} version - 版本
 * @property {string} vectorString - 向量字符串
 * @property {number} baseScore - 基本分数
 * @property {string} baseSeverity - 基本严重性
 * @property {number} temporalScore - 临时分数
 * @property {string} temporalSeverity - 临时严重性
 * @property {number} environmentalScore - 环境分数
 * @property {string} environmentalSeverity - 环境严重性
 * @property {boolean} isScopeChanged - 范围是否改变
 * @property {boolean} isModifiedScopeChanged - 修改后的范围是否改变
 * @property {CvssQualitativeMetricValue[]} qualitativeMetricValues - 定性指标值数组
 */
export declare interface CvssQualitativeMetricScore {
  version: string;
  vectorString: string;
  baseScore: number;
  baseSeverity: string;
  temporalScore: number;
  temporalSeverity: string;
  environmentalScore: number;
  environmentalSeverity: string;
  isScopeChanged: boolean;
  isModifiedScopeChanged: boolean;
  qualitativeMetricValues: CvssQualitativeMetricValue[];
}
