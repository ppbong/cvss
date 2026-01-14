// 导出类型定义
export type { 
  CvssMetricValue, 
  CvssMetric, 
  CvssV30ExploitabilityMetrics, 
  CvssV30ScopeMetrics, 
  CvssV30ImpactMetrics, 
  CvssV30BaseMetrics, 
  CvssV30TemporalMetrics, 
  CvssV30SecurityRequirementMetrics, 
  CvssV30ModifiedBaseMetrics, 
  CvssV30EnvironmentalMetrics, 
  CvssV31BaseMetrics, 
  CvssV31TemporalMetrics, 
  CvssV31EnvironmentalMetrics, 
  CvssQualitativeSeverityRating, 
  CvssQualitativeMetricValue, 
  CvssQualitativeMetricScore 
} from "./cvss-base";

// 导入数据结构
export { 
  CvssV30BaseMetricMap, 
  CvssV30TemporalMetricMap, 
  CvssV30EnvironmentalMetricMap,
  CvssV31BaseMetricMap, 
  CvssV31TemporalMetricMap, 
  CvssV31EnvironmentalMetricMap,
  CvssQualitativeSeverityRatingList
} from "./cvss-base.js";

// 导入功能函数和枚举
export { 
  // 枚举
  CvssVersion, 
  // 功能函数
  getSeverityRating, 
  parseVectorString, 
  calculateBaseScore, 
  calculateTemporalScore, 
  calculateEnvironmentalScore, 
  calculateCvssScore 
} from "./cvss-score.js";
