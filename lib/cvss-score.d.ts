import type { CvssMetric, CvssQualitativeMetricScore } from "./cvss-base";
/**
 * CVSS Version
 */
export declare enum CvssVersion {
    V30 = "3.0",
    V31 = "3.1"
}
/**
 * 获取严重性等级
 * @param score 评分
 * @returns 严重性等级
 */
export declare function getSeverityRating(score: number): string;
/**
 * 解析CVSS向量字符串
 * @param {string} vectorString CVSS向量字符串，示例：CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N
 * @returns {CvssQualitativeMetricScore} 指标评分对象
 */
export declare function parseVectorString(vectorString: string): CvssQualitativeMetricScore;
/**
 * 获取CVSS指标对象
 * @param version CVSS版本
 * @param metricCode 指标代码
 * @returns 指标对象
 */
export declare function findCvssMetric(version: string, metricCode: string): CvssMetric;
/**
 * 解决定性指标名称和评分
 * @param metricScore 指标评分对象
 * @returns 指标评分对象
 */
export declare function resolveQualitativeMetricNameAndValue(metricScore: CvssQualitativeMetricScore): CvssQualitativeMetricScore;
/**
 * 计算基本评分
 * @param metricScore 指标评分对象
 * @returns 指标评分对象
 */
export declare function calculateBaseScore(metricScore: CvssQualitativeMetricScore): CvssQualitativeMetricScore;
/**
 * 计算临时评分
 * @param metricScore 指标评分对象
 * @returns 指标评分对象
 */
export declare function calculateTemporalScore(metricScore: CvssQualitativeMetricScore): CvssQualitativeMetricScore;
/**
 * 计算环境评分
 * @param metricScore 指标评分对象
 * @returns 指标评分对象
 */
export declare function calculateEnvironmentalScore(metricScore: CvssQualitativeMetricScore): CvssQualitativeMetricScore;
/**
 * 计算CVSS评分
 * @param vectorString CVSS向量字符串
 * @returns 评分结果
 */
export declare function calculateCvssScore(vectorString: string): CvssQualitativeMetricScore;
