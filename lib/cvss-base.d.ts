import type { CvssV30BaseMetrics, CvssV30TemporalMetrics, CvssV30EnvironmentalMetrics } from "./cvss";
import type { CvssV31BaseMetrics, CvssV31TemporalMetrics, CvssV31EnvironmentalMetrics } from "./cvss";
import type { CvssQualitativeSeverityRating, CvssMetric } from "./cvss";
/**
 * CVSS V3.0 Base Metrics
 * @description 基本指标
 * @property {CvssMetric} attackVector - 攻击向量
 * @property {CvssMetric} attackComplexity - 攻击复杂度
 * @property {CvssMetric} privilegesRequired - 权限要求
 * @property {CvssMetric} userInteraction - 用户交互
 * @property {CvssMetric} scope - 范围
 * @property {CvssMetric} confidentialityImpact - 机密性影响
 * @property {CvssMetric} integrityImpact - 完整性影响
 * @property {CvssMetric} availabilityImpact - 可用性影响
 */
export declare const CvssV30BaseMetricMap: CvssV30BaseMetrics;
/**
 * CVSS V3.0 Temporal Metrics
 * @description 临时指标
 * @property {CvssMetric} exploitCodeMaturity - 利用代码成熟度
 * @property {CvssMetric} remediationLevel - 修复级别
 * @property {CvssMetric} reportConfidence - 报告置信度
 */
export declare const CvssV30TemporalMetricMap: CvssV30TemporalMetrics;
/**
 * CVSS V3.0 Environmental Metrics
 * @description 环境指标
 * @property {CvssMetric} confidentialityRequirement - 机密性需求
 * @property {CvssMetric} integrityRequirement - 完整性需求
 * @property {CvssMetric} availabilityRequirement - 可用性需求
 * @property {CvssMetric} modifiedAttackVector - 修改后的攻击向量
 * @property {CvssMetric} modifiedAttackComplexity - 修改后的攻击复杂度
 * @property {CvssMetric} modifiedPrivilegesRequired - 修改后的权限要求
 * @property {CvssMetric} modifiedUserInteraction - 修改后的用户交互
 * @property {CvssMetric} modifiedScope - 修改后的范围
 * @property {CvssMetric} modifiedConfidentialityImpact - 修改后的机密性影响
 * @property {CvssMetric} modifiedIntegrityImpact - 修改后的完整性影响
 * @property {CvssMetric} modifiedAvailabilityImpact - 修改后的可用性影响
 */
export declare const CvssV30EnvironmentalMetricMap: CvssV30EnvironmentalMetrics;
/**
 * CVSS V3.1 Base Metrics
 * @description 基本指标
 * @property {CvssMetric} attackVector - 攻击向量
 * @property {CvssMetric} attackComplexity - 攻击复杂度
 * @property {CvssMetric} privilegesRequired - 权限要求
 * @property {CvssMetric} userInteraction - 用户交互
 * @property {CvssMetric} scope - 范围
 * @property {CvssMetric} confidentiality - 机密性
 * @property {CvssMetric} integrity - 完整性
 * @property {CvssMetric} availability - 可用性
 */
export declare const CvssV31BaseMetricMap: CvssV31BaseMetrics;
/**
 * CVSS V3.1 Temporal Metrics
 * @description 临时指标
 * @property {CvssMetric} exploitCodeMaturity - 利用代码成熟度
 * @property {CvssMetric} remediationLevel - 修复级别
 * @property {CvssMetric} reportConfidence - 报告置信度
 */
export declare const CvssV31TemporalMetricMap: CvssV31TemporalMetrics;
/**
 * CVSS V3.1 Environmental Metrics
 * @description 环境指标
 * @property {CvssMetric} confidentialityRequirement - 机密性需求
 * @property {CvssMetric} integrityRequirement - 完整性需求
 * @property {CvssMetric} availabilityRequirement - 可用性需求
 * @property {CvssMetric} modifiedAttackVector - 修改后的攻击向量
 * @property {CvssMetric} modifiedAttackComplexity - 修改后的攻击复杂度
 * @property {CvssMetric} modifiedPrivilegesRequired - 修改后的权限要求
 * @property {CvssMetric} modifiedUserInteraction - 修改后的用户交互
 * @property {CvssMetric} modifiedScope - 修改后的范围
 * @property {CvssMetric} modifiedConfidentialityImpact - 修改后的机密性影响
 * @property {CvssMetric} modifiedIntegrityImpact - 修改后的完整性影响
 * @property {CvssMetric} modifiedAvailabilityImpact - 修改后的可用性影响
 */
export declare const CvssV31EnvironmentalMetricMap: CvssV31EnvironmentalMetrics;
/**
 * CVSS V3.1 Qualitative Severity Rating
 * @description 定性严重性等级
 */
export declare const CvssQualitativeSeverityRatingList: CvssQualitativeSeverityRating[];
/**
 * CVSS V3.0 Metric Code Map
 * @description CVSS V3.0指标代码映射
 */
export declare const CvssV30MetricCodeMap: Record<string, CvssMetric>;
/**
 * CVSS V3.1 Metric Code Map
 * @description CVSS V3.1指标代码映射
 */
export declare const CvssV31MetricCodeMap: Record<string, CvssMetric>;
