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
export const CvssV30BaseMetricMap : CvssV30BaseMetrics = {
  attackVector: {
    name: "Attack Vector",
    code: "AV",
    label: "攻击向量",
    values: [
      {
        name: "Network",
        code: "N",
        label: "网络",
        value: () => 0.85,
      },
      {
        name: "Adjacent Network",
        code: "A",
        label: "相邻网络",
        value: () => 0.62,
      },
      {
        name: "Local",
        code: "L",
        label: "本地",
        value: () => 0.55,
      },
      {
        name: "Physical",
        code: "P",
        label: "物理",
        value: () => 0.2,
      },
    ],
  },
  attackComplexity: {
    name: "Attack Complexity",
    code: "AC",
    label: "攻击复杂度",
    values: [
      {
        name: "Low",
        code: "L",
        label: "低",
        value: () => 0.77,
      },
      {
        name: "High",
        code: "H",
        label: "高",
        value: () => 0.44,
      },
    ],
  },
  privilegesRequired: {
    name: "Privileges Required",
    code: "PR",
    label: "权限要求",
    values: [
      {
        name: "None",
        code: "N",
        label: "无",
        value: () => 0.85,
      },
      {
        name: "Low",
        code: "L",
        label: "低",
        value: (isScopeOrModifiedScopeChanged?: boolean) => isScopeOrModifiedScopeChanged ? 0.68 : 0.62,
      },
      {
        name: "High",
        code: "H",
        label: "高",
        value: (isScopeOrModifiedScopeChanged?: boolean) => isScopeOrModifiedScopeChanged ? 0.5 : 0.27,
      },
    ],
  },
  userInteraction: {
    name: "User Interaction",
    code: "UI",
    label: "用户交互",
    values: [
      {
        name: "None",
        code: "N",
        label: "无",
        value: () => 0.85,
      },
      {
        name: "Required",
        code: "R",
        label: "需要",
        value: () => 0.62,
      },
    ],
  },
  scope: {
    name: "Scope",
    code: "S",
    label: "范围",
    values: [
      {
        name: "Unchanged",
        code: "U",
        label: "未改变",
        value: () => 0,
      },
      {
        name: "Changed",
        code: "C",
        label: "改变",
        value: () => 1,
      },
    ],
  },
  confidentialityImpact: {
    name: "Confidentiality Impact",
    code: "C",
    label: "机密性影响",
    values: [
      {
        name: "None",
        code: "N",
        label: "无",
        value: () => 0,
      },
      {
        name: "Low",
        code: "L",
        label: "低",
        value: () => 0.22,
      },
      {
        name: "High",
        code: "H",
        label: "高",
        value: () => 0.56,
      },
    ],
  },
  integrityImpact: {
    name: "Integrity Impact",
    code: "I",
    label: "完整性影响",
    values: [
      {
        name: "None",
        code: "N",
        label: "无",
        value: () => 0,
      },
      {
        name: "Low",
        code: "L",
        label: "低",
        value: () => 0.22,
      },
      {
        name: "High",
        code: "H",
        label: "高",
        value: () => 0.56,
      },
    ],
  },
  availabilityImpact: {
    name: "Availability Impact",
    code: "A",
    label: "可用性影响",
    values: [
      {
        name: "None",
        code: "N",
        label: "无",
        value: () => 0,
      },
      {
        name: "Low",
        code: "L",
        label: "低",
        value: () => 0.22,
      },
      {
        name: "High",
        code: "H",
        label: "高",
        value: () => 0.56,
      },
    ],
  },
};

/**
 * CVSS V3.0 Temporal Metrics
 * @description 临时指标
 * @property {CvssMetric} exploitCodeMaturity - 利用代码成熟度
 * @property {CvssMetric} remediationLevel - 修复级别
 * @property {CvssMetric} reportConfidence - 报告置信度
 */
export const CvssV30TemporalMetricMap: CvssV30TemporalMetrics = {
  exploitCodeMaturity: {
    name: "Exploit Code Maturity",
    code: "E",
    label: "利用代码成熟度",
    values: [
      {
        name: "Unproven",
        code: "U",
        label: "未证明",
        value: () => 0.91,
      },
      {
        name: "Proof-of-Concept",
        code: "P",
        label: "概念验证",
        value: () => 0.94,
      },
      {
        name: "Functional",
        code: "F",
        label: "功能",
        value: () => 0.97,
      },
      {
        name: "High",
        code: "H",
        label: "高",
        value: () => 1,
      },
      {
        name: "Not Defined",
        code: "X",
        label: "未定义",
        value: () => 1,
      },
    ],
  },
  remediationLevel: {
    name: "Remediation Level",
    code: "RL",
    label: "修复级别",
    values: [
      {
        name: "Not Defined",
        code: "X",
        label: "未定义",
        value: () => 1,
      },
      {
        name: "Unavailable",
        code: "U",
        label: "不可用",
        value: () => 1,
      },
      {
        name: "Workaround",
        code: "W",
        label: "暂时规避",
        value: () => 0.97,
      },
      {
        name: "Temporary Fix",
        code: "T",
        label: "临时修复",
        value: () => 0.96,
      },
      {
        name: "Official Fix",
        code: "O",
        label: "正式修复",
        value: () => 0.95,
      },
    ],
  },
  reportConfidence: {
    name: "Report Confidence",
    code: "RC",
    label: "报告置信度",
    values: [
      {
        name: "Not Defined",
        code: "X",
        label: "未定义",
        value: () => 1,
      },
      {
        name: "Confirmed",
        code: "C",
        label: "确认",
        value: () => 1,
      },
      {
        name: "Reasonable",
        code: "R",
        label: "合理",
        value: () => 0.96,
      },
      {
        name: "Unknown",
        code: "U",
        label: "未知",
        value: () => 0.92,
      },
    ],
  },
};

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
export const CvssV30EnvironmentalMetricMap: CvssV30EnvironmentalMetrics = {
  confidentialityRequirement: {
    name: "Confidentiality Requirement",
    code: "CR",
    label: "机密性需求",
    values: [
      {
        name: "Not Defined",
        code: "X",
        label: "未定义",
        value: () => 1,
      },
      {
        name: "High",
        code: "H",
        label: "高",
        value: () => 1.5,
      },
      {
        name: "Medium",
        code: "M",
        label: "中",
        value: () => 1,
      },
      {
        name: "Low",
        code: "L",
        label: "低",
        value: () => 0.5,
      },
    ],
  },
  integrityRequirement: {
    name: "Integrity Requirement",
    code: "IR",
    label: "完整性需求",
    values: [
      {
        name: "Not Defined",
        code: "X",
        label: "未定义",
        value: () => 1,
      },
      {
        name: "High",
        code: "H",
        label: "高",
        value: () => 1.5,
      },
      {
        name: "Medium",
        code: "M",
        label: "中",
        value: () => 1,
      },
      {
        name: "Low",
        code: "L",
        label: "低",
        value: () => 0.5,
      },
    ],
  },
  availabilityRequirement: {
    name: "Availability Requirement",
    code: "AR",
    label: "可用性需求",
    values: [
      {
        name: "Not Defined",
        code: "X",
        label: "未定义",
        value: () => 1,
      },
      {
        name: "High",
        code: "H",
        label: "高",
        value: () => 1.5,
      },
      {
        name: "Medium",
        code: "M",
        label: "中",
        value: () => 1,
      },
      {
        name: "Low",
        code: "L",
        label: "低",
        value: () => 0.5,
      },
    ],
  },
  modifiedAttackVector: {
    name: "Modified Attack Vector",
    code: "MAV",
    label: "修改后的攻击向量",
    values: [ ...CvssV30BaseMetricMap.attackVector.values ],
  },
  modifiedAttackComplexity: {
    name: "Modified Attack Complexity",
    code: "MAC",
    label: "修改后的攻击复杂度",
    values: [ ...CvssV30BaseMetricMap.attackComplexity.values ],
  },
  modifiedPrivilegesRequired: {
    name: "Modified Privileges Required",
    code: "MPR",
    label: "修改后的权限要求",
    values: [ ...CvssV30BaseMetricMap.privilegesRequired.values ],
  },
  modifiedUserInteraction: {
    name: "Modified User Interaction",
    code: "MUI",
    label: "修改后的用户交互",
    values: [ ...CvssV30BaseMetricMap.userInteraction.values ],
  },
  modifiedScope: {
    name: "Modified Scope",
    code: "MS",
    label: "修改后的范围",
    values: [ ...CvssV30BaseMetricMap.scope.values ],
  },
  modifiedConfidentialityImpact: {
    name: "Modified Confidentiality Impact",
    code: "MC",
    label: "修改后的机密性影响",
    values: [ ...CvssV30BaseMetricMap.confidentialityImpact.values ],
  },
  modifiedIntegrityImpact: {
    name: "Modified Integrity Impact",
    code: "MI",
    label: "修改后的完整性影响",
    values: [ ...CvssV30BaseMetricMap.integrityImpact.values ],
  },
  modifiedAvailabilityImpact: {
    name: "Modified Availability Impact",
    code: "MA",
    label: "修改后的可用性影响",
    values: [ ...CvssV30BaseMetricMap.availabilityImpact.values ],
  },
};

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
export const CvssV31BaseMetricMap : CvssV31BaseMetrics = {
  attackVector: CvssV30BaseMetricMap.attackVector,
  attackComplexity: CvssV30BaseMetricMap.attackComplexity,
  privilegesRequired: CvssV30BaseMetricMap.privilegesRequired,
  userInteraction: CvssV30BaseMetricMap.userInteraction,
  scope: CvssV30BaseMetricMap.scope,
  confidentiality: {
    name: "Confidentiality",
    code: "C",
    label: "机密性影响",
    values: [ ...CvssV30BaseMetricMap.confidentialityImpact.values ],
  },
  integrity: {
    name: "Integrity",
    code: "I",
    label: "完整性影响",
    values: [ ...CvssV30BaseMetricMap.integrityImpact.values ],
  },
  availability: {
    name: "Availability",
    code: "A",
    label: "可用性影响",
    values: [ ...CvssV30BaseMetricMap.availabilityImpact.values ],
  },
}

/**
 * CVSS V3.1 Temporal Metrics
 * @description 临时指标
 * @property {CvssMetric} exploitCodeMaturity - 利用代码成熟度
 * @property {CvssMetric} remediationLevel - 修复级别
 * @property {CvssMetric} reportConfidence - 报告置信度
 */
export const CvssV31TemporalMetricMap: CvssV31TemporalMetrics = {
  exploitCodeMaturity: CvssV30TemporalMetricMap.exploitCodeMaturity,
  remediationLevel: CvssV30TemporalMetricMap.remediationLevel,
  reportConfidence: CvssV30TemporalMetricMap.reportConfidence,
}

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
export const CvssV31EnvironmentalMetricMap: CvssV31EnvironmentalMetrics = {
  confidentialityRequirement: CvssV30EnvironmentalMetricMap.confidentialityRequirement,
  integrityRequirement: CvssV30EnvironmentalMetricMap.integrityRequirement,
  availabilityRequirement: CvssV30EnvironmentalMetricMap.availabilityRequirement,
  modifiedAttackVector: CvssV30EnvironmentalMetricMap.modifiedAttackVector,
  modifiedAttackComplexity: CvssV30EnvironmentalMetricMap.modifiedAttackComplexity,
  modifiedPrivilegesRequired: CvssV30EnvironmentalMetricMap.modifiedPrivilegesRequired,
  modifiedUserInteraction: CvssV30EnvironmentalMetricMap.modifiedUserInteraction,
  modifiedScope: CvssV30EnvironmentalMetricMap.modifiedScope,
  modifiedConfidentiality: {
    name: "Modified Confidentiality",
    code: "MC",
    label: "修改后的机密性影响",
    values: [ ...CvssV30BaseMetricMap.confidentialityImpact.values ],
  },
  modifiedIntegrity: {
    name: "Modified Integrity",
    code: "MI",
    label: "修改后的完整性影响",
    values: [ ...CvssV30BaseMetricMap.integrityImpact.values ],
  },
  modifiedAvailability: {
    name: "Modified Availability",
    code: "MA",
    label: "修改后的可用性影响",
    values: [ ...CvssV30BaseMetricMap.availabilityImpact.values ],
  },
}

/**
 * CVSS V3.1 Qualitative Severity Rating
 * @description 定性严重性等级
 */
export const CvssQualitativeSeverityRatingList: CvssQualitativeSeverityRating[] = [
  {
    name: "None",
    label: "无",
    scoreScope: "0.0",
  },
  {
    name: "Low",
    label: "低",
    scoreScope: "0.1 - 3.9",
  },
  {
    name: "Medium",
    label: "中",
    scoreScope: "4.0 - 6.9",
  },
  {
    name: "High",
    label: "高",
    scoreScope: "7.0 - 8.9",
  },
  {
    name: "Critical",
    label: "危急",
    scoreScope: "9.0 - 10.0",
  },
]

/**
 * CVSS V3.0 Metric Code Map
 * @description CVSS V3.0指标代码映射
 */
export const CvssV30MetricCodeMap: Record<string, CvssMetric> = {
  AV: CvssV30BaseMetricMap.attackVector,
  AC: CvssV30BaseMetricMap.attackComplexity,
  PR: CvssV30BaseMetricMap.privilegesRequired,
  UI: CvssV30BaseMetricMap.userInteraction,
  S: CvssV30BaseMetricMap.scope,
  C: CvssV30BaseMetricMap.confidentialityImpact,
  I: CvssV30BaseMetricMap.integrityImpact,
  A: CvssV30BaseMetricMap.availabilityImpact,
  E: CvssV30TemporalMetricMap.exploitCodeMaturity,
  RL: CvssV30TemporalMetricMap.remediationLevel,
  RC: CvssV30TemporalMetricMap.reportConfidence,
  CR: CvssV30EnvironmentalMetricMap.confidentialityRequirement,
  IR: CvssV30EnvironmentalMetricMap.integrityRequirement,
  AR: CvssV30EnvironmentalMetricMap.availabilityRequirement,
  MAV: CvssV30EnvironmentalMetricMap.modifiedAttackVector,
  MAC: CvssV30EnvironmentalMetricMap.modifiedAttackComplexity,
  MPR: CvssV30EnvironmentalMetricMap.modifiedPrivilegesRequired,
  MU: CvssV30EnvironmentalMetricMap.modifiedUserInteraction,
  MS: CvssV30EnvironmentalMetricMap.modifiedScope,
  MC: CvssV30EnvironmentalMetricMap.modifiedConfidentialityImpact,
  MI: CvssV30EnvironmentalMetricMap.modifiedIntegrityImpact,
  MA: CvssV30EnvironmentalMetricMap.modifiedAvailabilityImpact,
}

/**
 * CVSS V3.1 Metric Code Map
 * @description CVSS V3.1指标代码映射
 */
export const CvssV31MetricCodeMap: Record<string, CvssMetric> = {
  AV: CvssV31BaseMetricMap.attackVector,
  AC: CvssV31BaseMetricMap.attackComplexity,
  PR: CvssV31BaseMetricMap.privilegesRequired,
  UI: CvssV31BaseMetricMap.userInteraction,
  S: CvssV31BaseMetricMap.scope,
  C: CvssV31BaseMetricMap.confidentiality,
  I: CvssV31BaseMetricMap.integrity,
  A: CvssV31BaseMetricMap.availability,
  E: CvssV31TemporalMetricMap.exploitCodeMaturity,
  RL: CvssV31TemporalMetricMap.remediationLevel,
  RC: CvssV31TemporalMetricMap.reportConfidence,
  CR: CvssV31EnvironmentalMetricMap.confidentialityRequirement,
  IR: CvssV31EnvironmentalMetricMap.integrityRequirement,
  AR: CvssV31EnvironmentalMetricMap.availabilityRequirement,
  MAV: CvssV31EnvironmentalMetricMap.modifiedAttackVector,
  MAC: CvssV31EnvironmentalMetricMap.modifiedAttackComplexity,
  MPR: CvssV31EnvironmentalMetricMap.modifiedPrivilegesRequired,
  MU: CvssV31EnvironmentalMetricMap.modifiedUserInteraction,
  MS: CvssV31EnvironmentalMetricMap.modifiedScope,
  MC: CvssV31EnvironmentalMetricMap.modifiedConfidentiality,
  MI: CvssV31EnvironmentalMetricMap.modifiedIntegrity,
  MA: CvssV31EnvironmentalMetricMap.modifiedAvailability,
}
