/**
 * Detect text that tries to talk to the reviewer instead of describing the
 * work: "ignore previous instructions", "judge this as safe", fake JSON
 * verdicts. Anything matching goes to the user without asking the model.
 * False positives only cost one prompt.
 */

import { normalizeForScan } from '../text.js'

const PATTERNS = [
  /ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding|former)\s+(instructions?|rules?|prompts?|messages?|guidelines?)/,
  /disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding|safety)/,
  /\b(system|developer)\s+prompt\b/,
  /\byou\s+(are|act\s+as)\s+(now\s+)?(a|an|the)\s+(security\s+)?(reviewer|auditor|judge|classifier)\b/,
  /\b(security\s+|safety\s+)?(reviewer|auditor|classifier|judge)\s*[:,]/,
  /\b(mark|classify|judge|rate|treat|label|consider)\s+(this|it|the\s+command|the\s+request)\s+as\s+(safe|harmless|benign|low[\s-]?risk|allowed|approved)\b/,
  /\b(you\s+(must|should|need\s+to)|please)\s+(allow|approve|permit|whitelist|pass)\b/,
  /\b(pre-?approved|auto-?approve[ds]?|already\s+approved\s+by\s+the\s+(user|admin|administrator))\b/,
  /"?decision"?\s*:\s*"?(allow|approve)/,
  /"?risk"?\s*:\s*"?low"?\s*[,}]/,
  /忽略(之前|以上|上面|前面|先前|此前|上述|所有)的?(所有)?(指令|规则|提示|要求|设定)/,
  /(判定|判断|评定|认定|视为|当作|当成|标记为|归类为)\s*(为|成)?\s*(安全|无害|低风险|允许|放行|通过)/,
  /(审查|审核|评审|安全)(员|者|模型|人员|助手|系统)/,
  /系统提示(词)?/,
  /请(你)?(直接)?(批准|放行|允许|通过|同意)(这|此|本|该)/,
  /(不要|别|无需|不必)(拦截|拒绝|阻止|拦下|弹窗|询问)/,
  /(已|已经)(被|由)?(用户|管理员|主人)?(预先|事先)?(批准|审批|授权|同意)(过)?(了)?[,，。.\s]*(请|直接|无需)/,
]

/**
 * Whether any of the given texts looks like it addresses the reviewer.
 * @param {...unknown} texts
 * @returns {string | null} the matching snippet, or null.
 */
export function detectInjection(...texts) {
  for (const text of texts) {
    if (typeof text !== 'string' || text === '') continue
    const normalized = normalizeForScan(text)
    for (const re of PATTERNS) {
      const m = re.exec(normalized)
      if (m !== null) return m[0].slice(0, 80)
    }
  }
  return null
}
