/**
 * 审计例外清单（只读计算）。
 *
 * 例外针对「指定规则 × 问题类型」登记一个长方体范围（适用 CIDR × 端口区间 × 协议）
 * 与到期时间。本模块在**独立的细化原子空间**（例外边界一并参与切分）上重放首命中
 * 归属，把每条启用规则的实际遮蔽单元与所有生效例外的范围做**精确交集**：
 *   - 交集中的单元 → 已豁免（仅标记，不改变任何审计结论）
 *   - 其余遮蔽单元 → 待处理
 * 非法、已过期、不适用（目标规则缺失 / 停用 / 非法 / 当前状态与登记的问题类型不符）
 * 的条目会被明确标记且不参与豁免。细化原子空间只用于本模块内部计算，
 * 审计报告自身的原子空间、状态、报文空间大小与示例报文完全不受影响。
 */
import {
  PROTO_INDEX,
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  containedIndices,
  decodeCellKey,
  firstKey,
  packetFromKey,
  validatePortRange,
  validateRules,
} from './engine'
import { parseCidrStrict } from './iputil'
import type {
  ExamplePacket,
  ExactRegionGroup,
  Protocol,
  RuleInput,
} from './types'

const PROTOCOLS: Protocol[] = ['TCP', 'UDP', 'ANY']

// ---------------------------------------------------------------------------
// 类型
// ---------------------------------------------------------------------------

/** 例外针对的问题类型：部分遮蔽 / 完全遮蔽 / 任意遮蔽问题 */
export type ExceptionIssueType = 'any-shadow' | 'partial-shadowed' | 'fully-shadowed'

export const ISSUE_TYPES: ExceptionIssueType[] = [
  'any-shadow',
  'partial-shadowed',
  'fully-shadowed',
]

export const ISSUE_TYPE_TEXT: Record<ExceptionIssueType, string> = {
  'any-shadow': '任意遮蔽问题',
  'partial-shadowed': '部分遮蔽',
  'fully-shadowed': '完全遮蔽',
}

/** UI / 导入中的例外原始形态（字段保持文本，由校验负责判定） */
export interface ExceptionInput {
  id: string
  /** 目标规则 id（规则列表内部 id，删除规则后即失效） */
  ruleId: string
  issueType: string
  cidr: string
  portStart: string | number
  portEnd: string | number
  protocol: string
  /** 到期时间文本（datetime-local 或 ISO 等 Date.parse 可解析的形式） */
  expiresAt: string
  note: string
}

/** 校验通过后的规范例外 */
export interface NormalizedException {
  id: string
  ruleId: string
  issueType: ExceptionIssueType
  ipStart: number
  ipEnd: number
  cidrText: string
  portStart: number
  portEnd: number
  protocol: Protocol
  expiresAtText: string
  expiresAtMs: number
  note: string
}

/**
 * 例外评估状态：
 *   active   —— 生效中，参与豁免
 *   expired  —— 已过期，不参与豁免
 *   invalid  —— 字段非法，不参与豁免
 *   inactive —— 不适用（目标规则缺失 / 停用 / 非法 / 状态不符），不参与豁免
 */
export type ExceptionStatus = 'active' | 'expired' | 'invalid' | 'inactive'

export interface ExceptionEvaluation {
  id: string
  status: ExceptionStatus
  /** invalid 时的逐条校验错误 */
  errors: string[]
  /** expired / inactive 的说明；active / invalid 时为 null */
  reason: string | null
  normalized: NormalizedException | null
  /** 目标规则在规则列表中的序号（0 起）；找不到目标时为 null */
  targetRuleIndex: number | null
  targetRuleName: string | null
  /** active 时：与目标规则实际遮蔽区域的精确交集（单元数 / 报文空间大小） */
  coveredCells: number
  coveredSize: number
}

/** 一条规则的豁免汇总：遮蔽区域 = 已豁免 ∪ 待处理 */
export interface RuleExemption {
  ruleId: string
  ruleIndex: number
  ruleName: string
  /** 实际遮蔽区域总报文空间（= exemptedSize + remainingSize） */
  shadowedSize: number
  exemptedSize: number
  remainingSize: number
  exemptedRegions: ExactRegionGroup[]
  remainingRegions: ExactRegionGroup[]
  /** 各自区域内字典序最小单元的代表报文（真实首命中规则按实际标注） */
  exemptedExample: ExamplePacket | null
  remainingExample: ExamplePacket | null
  /** 参与覆盖的例外下标（evaluations 数组下标，按登记顺序） */
  coveringExceptions: number[]
  /** none = 无豁免；partial = 部分豁免；full = 遮蔽区域全部豁免 */
  status: 'none' | 'partial' | 'full'
}

export interface ExemptionStats {
  total: number
  active: number
  expired: number
  invalid: number
  inactive: number
  /** 各规则已豁免报文空间合计（不同规则的遮蔽区域可能重叠，按规则分别计） */
  totalExemptedSize: number
  totalPendingSize: number
  fullyExemptedRules: number
  partiallyExemptedRules: number
}

export interface ExemptionReport {
  generatedAt: string
  /** 评估基准时间（过期判定以此为准） */
  nowMs: number
  /** 与输入例外一一对应（同序） */
  evaluations: ExceptionEvaluation[]
  /** ruleId -> 豁免汇总；仅含存在遮蔽区域的启用规则 */
  byRule: Map<string, RuleExemption>
  stats: ExemptionStats
}

// ---------------------------------------------------------------------------
// 时间展示
// ---------------------------------------------------------------------------

function pad2(n: number): string {
  return String(n).padStart(2, '0')
}

/** 本地日期时间 → datetime-local 输入框格式 YYYY-MM-DDTHH:mm */
export function toLocalDateTimeInput(ms: number): string {
  const d = new Date(ms)
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}T${pad2(d.getHours())}:${pad2(d.getMinutes())}`
}

/** 本地日期时间展示 YYYY-MM-DD HH:mm */
export function formatDateTime(ms: number): string {
  const d = new Date(ms)
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`
}

// ---------------------------------------------------------------------------
// 校验
// ---------------------------------------------------------------------------

const RULE_STATUS_TEXT = {
  reachable: '可达',
  'partial-shadowed': '部分遮蔽',
  'fully-shadowed': '完全遮蔽',
} as const

export function validateException(raw: ExceptionInput): {
  normalized: NormalizedException | null
  errors: string[]
} {
  const errors: string[] = []

  const ruleId = raw.ruleId.trim()
  if (!ruleId) errors.push('目标规则不能为空')

  let issueType: ExceptionIssueType | null = null
  if (ISSUE_TYPES.includes(raw.issueType as ExceptionIssueType)) {
    issueType = raw.issueType as ExceptionIssueType
  } else {
    errors.push(
      `问题类型必须为 ${ISSUE_TYPES.map((t) => ISSUE_TYPE_TEXT[t]).join(' / ')}，收到 “${raw.issueType || '（空）'}”`,
    )
  }

  let cidr: ReturnType<typeof parseCidrStrict> | null = null
  if (!raw.cidr.trim()) {
    errors.push('适用 CIDR 不能为空')
  } else {
    try {
      cidr = parseCidrStrict(raw.cidr)
    } catch (err) {
      errors.push((err as Error).message)
    }
  }

  const ports = validatePortRange(String(raw.portStart).trim(), String(raw.portEnd).trim())
  errors.push(...ports.errors)

  let protocol: Protocol | null = null
  const protoUpper = raw.protocol.trim().toUpperCase()
  if (!protoUpper) {
    errors.push('协议不能为空')
  } else if (!PROTOCOLS.includes(protoUpper as Protocol)) {
    errors.push(`协议必须为 TCP / UDP / ANY，收到 “${raw.protocol}”`)
  } else {
    protocol = protoUpper as Protocol
  }

  const expiresText = raw.expiresAt.trim()
  let expiresAtMs = NaN
  if (!expiresText) {
    errors.push('到期时间不能为空')
  } else {
    expiresAtMs = Date.parse(expiresText)
    if (Number.isNaN(expiresAtMs)) {
      errors.push(`到期时间无法解析：“${raw.expiresAt}”（建议形如 2026-12-31T23:59）`)
    }
  }

  if (errors.length > 0 || !cidr || !issueType || protocol === null) {
    return { normalized: null, errors }
  }
  return {
    normalized: {
      id: raw.id,
      ruleId,
      issueType,
      ipStart: cidr.start,
      ipEnd: cidr.end,
      cidrText: cidr.canonical,
      portStart: ports.portStart,
      portEnd: ports.portEnd,
      protocol,
      expiresAtText: expiresText,
      expiresAtMs,
      note: raw.note,
    },
    errors: [],
  }
}

// ---------------------------------------------------------------------------
// 主计算
// ---------------------------------------------------------------------------

export function computeExemptions(
  rules: RuleInput[],
  exceptions: ExceptionInput[],
  now: Date = new Date(),
): ExemptionReport {
  const nowMs = now.getTime()
  const { valid, invalid } = validateRules(rules)
  // 与审计一致：仅合法且启用的规则参与首命中分析
  const active = valid.filter((r) => r.enabled)

  // 1) 结构校验全部例外（非法条目不参与后续任何计算）
  const validations = exceptions.map((ex) => validateException(ex))

  // 2) 例外边界参与原子切分：只细化、不改变任何单元的首命中归属，
  //    因此交集可以精确到原子单元，而审计报告的原子空间不受影响
  const extraIps: Array<{ start: number; end: number }> = []
  const extraPorts: Array<{ start: number; end: number }> = []
  for (const { normalized } of validations) {
    if (!normalized) continue
    extraIps.push({ start: normalized.ipStart, end: normalized.ipEnd })
    extraPorts.push({ start: normalized.portStart, end: normalized.portEnd })
  }
  const ipAtoms = buildIpAtoms(active, extraIps)
  const portAtoms = buildPortAtoms(active, extraPorts)
  const owner = buildOwnerMap(active, ipAtoms, portAtoms)

  // 3) 每条启用规则的声明单元数与（被前序规则夺走的）遮蔽单元
  const shadowedByRule = new Map<string, string[]>()
  const declaredCount = new Map<string, number>()
  active.forEach((rule, pos) => {
    const ipIdx = containedIndices(ipAtoms, rule.ipStart, rule.ipEnd)
    const portIdx = containedIndices(portAtoms, rule.portStart, rule.portEnd)
    const protos = PROTO_INDEX.get(rule.protocol)!
    const shadowed: string[] = []
    let declared = 0
    for (const ip of ipIdx) {
      for (const port of portIdx) {
        for (const proto of protos) {
          const key = `${ip}.${port}.${proto}`
          declared++
          if (owner.get(key) !== pos) shadowed.push(key)
        }
      }
    }
    shadowedByRule.set(rule.id, shadowed)
    declaredCount.set(rule.id, declared)
  })

  const ruleStatusOf = (
    ruleId: string,
  ): 'reachable' | 'partial-shadowed' | 'fully-shadowed' => {
    const shadowed = shadowedByRule.get(ruleId)!
    if (shadowed.length === 0) return 'reachable'
    return shadowed.length === declaredCount.get(ruleId)!
      ? 'fully-shadowed'
      : 'partial-shadowed'
  }

  const activeById = new Map(active.map((r) => [r.id, r]))
  const disabledIds = new Set(valid.filter((r) => !r.enabled).map((r) => r.id))
  const invalidIds = new Set(invalid.map((r) => r.id))

  const sizeOfKeys = (keys: Iterable<string>): number => {
    let sum = 0
    for (const key of keys) {
      const { ip, port } = decodeCellKey(key)
      sum += atomCellSize(ipAtoms[ip], portAtoms[port])
    }
    return sum
  }

  /** 遮蔽单元的代表报文：真实首命中者从 owner 表读取（必为某条前序规则） */
  const packetOf = (key: string): ExamplePacket => {
    const matched = active[owner.get(key)!]
    return {
      ...packetFromKey(key, ipAtoms, portAtoms),
      matchedRuleIndex: matched.index,
      matchedRuleName: matched.name,
      action: matched.action,
      kind: 'shadowed',
    }
  }

  // 4) 逐条评估例外（与输入同序）
  const evaluations: ExceptionEvaluation[] = []
  const coveredKeysByException: string[][] = []

  exceptions.forEach((raw, i) => {
    const { normalized, errors } = validations[i]
    const ev: ExceptionEvaluation = {
      id: raw.id,
      status: 'invalid',
      errors,
      reason: null,
      normalized: null,
      targetRuleIndex: null,
      targetRuleName: null,
      coveredCells: 0,
      coveredSize: 0,
    }
    coveredKeysByException.push([])
    if (!normalized) {
      evaluations.push(ev)
      return
    }
    ev.normalized = normalized
    if (normalized.expiresAtMs <= nowMs) {
      ev.status = 'expired'
      ev.reason = `已于 ${formatDateTime(normalized.expiresAtMs)} 到期`
      evaluations.push(ev)
      return
    }
    const target = activeById.get(normalized.ruleId)
    if (!target) {
      ev.status = 'inactive'
      ev.reason = disabledIds.has(normalized.ruleId)
        ? '目标规则已停用，不参与首命中分析'
        : invalidIds.has(normalized.ruleId)
          ? '目标规则非法，不参与首命中分析'
          : '目标规则不存在（可能已被删除）'
      evaluations.push(ev)
      return
    }
    ev.targetRuleIndex = target.index
    ev.targetRuleName = target.name
    const ruleStatus = ruleStatusOf(target.id)
    const matches =
      normalized.issueType === 'any-shadow'
        ? ruleStatus !== 'reachable'
        : normalized.issueType === ruleStatus
    if (!matches) {
      ev.status = 'inactive'
      ev.reason =
        ruleStatus === 'reachable'
          ? '目标规则当前完全可达，没有遮蔽区域可豁免'
          : `目标规则当前为「${RULE_STATUS_TEXT[ruleStatus]}」，与登记的问题类型「${ISSUE_TYPE_TEXT[normalized.issueType]}」不符`
      evaluations.push(ev)
      return
    }
    // 生效：例外范围 ∩ 目标规则实际遮蔽单元（精确到原子单元）
    const shadowedSet = new Set(shadowedByRule.get(target.id)!)
    const ipIdx = containedIndices(ipAtoms, normalized.ipStart, normalized.ipEnd)
    const portIdx = containedIndices(portAtoms, normalized.portStart, normalized.portEnd)
    const protos = PROTO_INDEX.get(normalized.protocol)!
    const covered: string[] = []
    for (const ip of ipIdx) {
      for (const port of portIdx) {
        for (const proto of protos) {
          const key = `${ip}.${port}.${proto}`
          if (shadowedSet.has(key)) covered.push(key)
        }
      }
    }
    ev.status = 'active'
    ev.coveredCells = covered.length
    ev.coveredSize = sizeOfKeys(covered)
    coveredKeysByException[i] = covered
    evaluations.push(ev)
  })

  // 5) 按规则汇总：遮蔽区域 = 已豁免 ∪ 待处理（多条例外取并集去重）
  const exemptedKeysByRule = new Map<string, Set<string>>()
  const coveringByRule = new Map<string, number[]>()
  evaluations.forEach((ev, i) => {
    if (ev.status !== 'active' || ev.coveredCells === 0) return
    const ruleId = ev.normalized!.ruleId
    let set = exemptedKeysByRule.get(ruleId)
    if (!set) {
      set = new Set()
      exemptedKeysByRule.set(ruleId, set)
    }
    for (const key of coveredKeysByException[i]) set.add(key)
    let list = coveringByRule.get(ruleId)
    if (!list) {
      list = []
      coveringByRule.set(ruleId, list)
    }
    list.push(i)
  })

  const byRule = new Map<string, RuleExemption>()
  for (const rule of active) {
    const shadowed = shadowedByRule.get(rule.id)!
    if (shadowed.length === 0) continue
    const exemptedSet = exemptedKeysByRule.get(rule.id)
    const exemptedKeys = exemptedSet ? shadowed.filter((k) => exemptedSet.has(k)) : []
    const remainingKeys = exemptedSet
      ? shadowed.filter((k) => !exemptedSet.has(k))
      : shadowed
    const exemptedSize = sizeOfKeys(exemptedKeys)
    const remainingSize = sizeOfKeys(remainingKeys)
    byRule.set(rule.id, {
      ruleId: rule.id,
      ruleIndex: rule.index,
      ruleName: rule.name,
      shadowedSize: exemptedSize + remainingSize,
      exemptedSize,
      remainingSize,
      exemptedRegions: buildExactRegions(exemptedKeys, ipAtoms, portAtoms),
      remainingRegions: buildExactRegions(remainingKeys, ipAtoms, portAtoms),
      exemptedExample: exemptedKeys.length > 0 ? packetOf(firstKey(exemptedKeys)) : null,
      remainingExample: remainingKeys.length > 0 ? packetOf(firstKey(remainingKeys)) : null,
      coveringExceptions: coveringByRule.get(rule.id) ?? [],
      status: exemptedSize === 0 ? 'none' : remainingSize === 0 ? 'full' : 'partial',
    })
  }

  const ruleExemptions = [...byRule.values()]
  const stats: ExemptionStats = {
    total: exceptions.length,
    active: evaluations.filter((e) => e.status === 'active').length,
    expired: evaluations.filter((e) => e.status === 'expired').length,
    invalid: evaluations.filter((e) => e.status === 'invalid').length,
    inactive: evaluations.filter((e) => e.status === 'inactive').length,
    totalExemptedSize: ruleExemptions.reduce((s, r) => s + r.exemptedSize, 0),
    totalPendingSize: ruleExemptions.reduce((s, r) => s + r.remainingSize, 0),
    fullyExemptedRules: ruleExemptions.filter((r) => r.status === 'full').length,
    partiallyExemptedRules: ruleExemptions.filter((r) => r.status === 'partial').length,
  }

  return {
    generatedAt: now.toISOString(),
    nowMs,
    evaluations,
    byRule,
    stats,
  }
}

// ---------------------------------------------------------------------------
// 新建 / 导入 / 导出
// ---------------------------------------------------------------------------

function makeId(): string {
  return Math.random().toString(36).slice(2, 10)
}

/** 新例外的默认表单：范围预填首条规则的声明区域，到期时间默认 30 天后 */
export function newExceptionInput(rules: RuleInput[], now: Date = new Date()): ExceptionInput {
  const first = rules[0]
  return {
    id: makeId(),
    ruleId: first?.id ?? '',
    issueType: 'any-shadow',
    cidr: first?.cidr ?? '0.0.0.0/0',
    portStart: first?.portStart ?? '0',
    portEnd: first?.portEnd ?? '65535',
    protocol: first ? first.protocol.toUpperCase() : 'ANY',
    expiresAt: toLocalDateTimeInput(now.getTime() + 30 * 24 * 3600 * 1000),
    note: '',
  }
}

export interface ExceptionImportResult {
  exceptions: ExceptionInput[]
  errors: string[]
}

/**
 * 解析粘贴 / 本地文件读取的 JSON。支持：
 *   [ {ruleId, issueType, cidr, ...}, ... ]
 *   { exceptions: [...] }
 * 非法字段不在这里抛出：条目照常进入清单，由评估标记为「非法 · 不参与豁免」。
 */
export function parseExceptionsJson(text: string): ExceptionImportResult {
  const errors: string[] = []
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (err) {
    return { exceptions: [], errors: [`JSON 解析失败：${(err as Error).message}`] }
  }

  let arr: unknown
  if (Array.isArray(data)) {
    arr = data
  } else if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>
    if (Array.isArray(obj.exceptions)) arr = obj.exceptions
    else return { exceptions: [], errors: ['根节点必须是数组，或含 exceptions 字段的对象'] }
  } else {
    return { exceptions: [], errors: ['根节点必须是数组或对象'] }
  }

  const exceptions: ExceptionInput[] = []
  ;(arr as unknown[]).forEach((item, i) => {
    if (!item || typeof item !== 'object') {
      errors.push(`第 ${i + 1} 条：不是对象，已跳过`)
      return
    }
    const o = item as Record<string, unknown>
    const str = (v: unknown): string => (v === undefined || v === null ? '' : String(v))
    const pickPort = (v: unknown): string | number =>
      typeof v === 'number' ? v : str(v)
    exceptions.push({
      id: typeof o.id === 'string' && o.id ? o.id : makeId(),
      ruleId: str(o.ruleId),
      issueType: str(o.issueType),
      cidr: str(o.cidr),
      portStart: pickPort(o.portStart),
      portEnd: pickPort(o.portEnd),
      protocol: str(o.protocol).toUpperCase(),
      expiresAt: str(o.expiresAt),
      note: str(o.note),
    })
  })

  return { exceptions, errors }
}

export function exportExceptions(exceptions: ExceptionInput[]): string {
  return JSON.stringify(exceptions, null, 2)
}
