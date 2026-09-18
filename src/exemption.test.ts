/** 审计例外清单自检：node --test 风格的轻量断言脚本（零额外依赖） */
import assert from 'node:assert'
import {
  computeExemptions,
  exportExceptions,
  newExceptionInput,
  parseExceptionsJson,
} from './audit/exemption'
import type { ExceptionInput } from './audit/exemption'
import type { RuleInput } from './audit/types'

let passed = 0
function test(name: string, fn: () => void) {
  fn()
  passed++
  console.log(`  ✓ ${name}`)
}

let seq = 0
function rule(partial: Partial<RuleInput>): RuleInput {
  return {
    id: partial.id ?? `r${seq++}`,
    name: partial.name ?? `R${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

function ex(partial: Partial<ExceptionInput>): ExceptionInput {
  return {
    id: partial.id ?? `ex${seq++}`,
    ruleId: partial.ruleId ?? '',
    issueType: partial.issueType ?? 'any-shadow',
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    expiresAt: partial.expiresAt ?? '2099-12-31T23:59',
    note: partial.note ?? '',
  }
}

/** 固定的评估基准时间（本地时区，分钟对齐） */
const NOW = new Date('2026-09-18T12:00:00')

/** 场景 A：B 的前半 /25 被 A 遮蔽（部分遮蔽） */
function setupPartial() {
  return [
    rule({ id: 'A', name: 'A', cidr: '10.0.0.0/25' }),
    rule({ id: 'B', name: 'B', cidr: '10.0.0.0/24' }),
  ]
}

/** 场景 B：B 与 A 完全同区域（完全遮蔽） */
function setupFull() {
  return [
    rule({ id: 'A', name: 'A', cidr: '10.0.0.0/24' }),
    rule({ id: 'B', name: 'B', cidr: '10.0.0.0/24' }),
  ]
}

// --- 校验：非法条目标记为 invalid 且不参与豁免 ---
test('非法例外逐类标记：CIDR / 端口 / 协议 / 到期时间 / 目标规则 / 问题类型', () => {
  const rules = setupPartial()
  const cases: Array<[Partial<ExceptionInput>, RegExp]> = [
    [{ cidr: '10.0.0.1/24' }, /主机位非零/],
    [{ portStart: '100', portEnd: '50' }, /端口区间倒置/],
    [{ protocol: 'ICMP' }, /协议必须为/],
    [{ expiresAt: '' }, /到期时间不能为空/],
    [{ expiresAt: 'not-a-date' }, /无法解析/],
    [{ ruleId: '' }, /目标规则不能为空/],
    [{ issueType: 'unknown' }, /问题类型必须为/],
  ]
  for (const [patch, pattern] of cases) {
    const report = computeExemptions(rules, [ex({ ruleId: 'B', ...patch })], NOW)
    const ev = report.evaluations[0]
    assert.equal(ev.status, 'invalid', `${pattern} 应为 invalid`)
    assert.match(ev.errors.join('\n'), pattern)
    // 非法条目不参与豁免
    assert.equal(report.byRule.get('B')!.exemptedSize, 0)
  }
})

// --- 过期判定 ---
test('过期例外不参与豁免；恰好到期视为过期；未来时间生效', () => {
  const rules = setupPartial()
  const past = computeExemptions(
    rules,
    [ex({ ruleId: 'B', cidr: '10.0.0.0/25', expiresAt: '2026-09-18T11:59' })],
    NOW,
  )
  assert.equal(past.evaluations[0].status, 'expired')
  assert.match(past.evaluations[0].reason!, /到期/)
  assert.equal(past.byRule.get('B')!.exemptedSize, 0)
  assert.equal(past.byRule.get('B')!.remainingSize, 128 * 65536 * 2)

  const boundary = computeExemptions(
    rules,
    [ex({ ruleId: 'B', cidr: '10.0.0.0/25', expiresAt: '2026-09-18T12:00' })],
    NOW,
  )
  assert.equal(boundary.evaluations[0].status, 'expired')

  const future = computeExemptions(
    rules,
    [ex({ ruleId: 'B', cidr: '10.0.0.0/25', expiresAt: '2026-09-18T12:01' })],
    NOW,
  )
  assert.equal(future.evaluations[0].status, 'active')
  assert.equal(future.byRule.get('B')!.exemptedSize, 128 * 65536 * 2)
})

// --- 精确交集：IP 维 ---
test('精确交集：例外 /26 只豁免遮蔽 /25 的前半，大小与区域精确', () => {
  const rules = setupPartial()
  const report = computeExemptions(
    rules,
    [ex({ ruleId: 'B', cidr: '10.0.0.0/26', note: 'n1' })],
    NOW,
  )
  const ev = report.evaluations[0]
  assert.equal(ev.status, 'active')
  assert.equal(ev.coveredSize, 64 * 65536 * 2)

  const re = report.byRule.get('B')!
  assert.equal(re.shadowedSize, 128 * 65536 * 2)
  assert.equal(re.exemptedSize, 64 * 65536 * 2)
  assert.equal(re.remainingSize, 64 * 65536 * 2)
  assert.equal(re.status, 'partial')
  assert.deepEqual(re.coveringExceptions, [0])

  // 已豁免区域：10.0.0.0/26 × 全端口 × TCP+UDP
  const exemptTcp = re.exemptedRegions.find((g) => g.protocol === 'TCP')!
  assert.deepEqual(exemptTcp.rows.flatMap((r) => r.cidrs), ['10.0.0.0/26'])
  assert.equal(exemptTcp.rows[0].portStart, 0)
  assert.equal(exemptTcp.rows[0].portEnd, 65535)
  // 待处理区域：10.0.0.64/26
  const remainTcp = re.remainingRegions.find((g) => g.protocol === 'TCP')!
  assert.deepEqual(remainTcp.rows.flatMap((r) => r.cidrs), ['10.0.0.64/26'])

  // 代表报文确定且命中真实首命中规则 A
  assert.equal(re.exemptedExample!.srcIp, '10.0.0.1')
  assert.equal(re.exemptedExample!.srcPort, 0)
  assert.equal(re.exemptedExample!.protocol, 'TCP')
  assert.equal(re.exemptedExample!.matchedRuleName, 'A')
  assert.equal(re.exemptedExample!.matchedRuleIndex, 0)
  assert.equal(re.exemptedExample!.kind, 'shadowed')
  assert.equal(re.remainingExample!.srcIp, '10.0.0.65')
  assert.equal(re.remainingExample!.matchedRuleName, 'A')
})

// --- 精确交集：端口维与协议维 ---
test('精确交集：端口区间与协议维分别独立取交', () => {
  const rules = setupFull()
  const tcpOnly = computeExemptions(
    rules,
    [ex({ ruleId: 'B', cidr: '10.0.0.0/24', portStart: '80', portEnd: '443', protocol: 'TCP' })],
    NOW,
  )
  const re = tcpOnly.byRule.get('B')!
  assert.equal(re.exemptedSize, 256 * 364)
  assert.equal(re.remainingSize, 256 * 65536 * 2 - 256 * 364)
  // 待处理 TCP 被切成两段，UDP 整段保留
  const remainTcp = re.remainingRegions.find((g) => g.protocol === 'TCP')!
  assert.deepEqual(
    remainTcp.rows.map((r) => [r.portStart, r.portEnd]),
    [
      [0, 79],
      [444, 65535],
    ],
  )
  const remainUdp = re.remainingRegions.find((g) => g.protocol === 'UDP')!
  assert.deepEqual(
    remainUdp.rows.map((r) => [r.portStart, r.portEnd]),
    [[0, 65535]],
  )
  assert.equal(re.exemptedExample!.srcPort, 80)
  assert.equal(re.exemptedExample!.protocol, 'TCP')
  assert.equal(re.remainingExample!.srcPort, 0)

  const anyProto = computeExemptions(
    rules,
    [ex({ ruleId: 'B', cidr: '10.0.0.0/24', portStart: '80', portEnd: '443', protocol: 'ANY' })],
    NOW,
  )
  assert.equal(anyProto.byRule.get('B')!.exemptedSize, 256 * 364 * 2)
})

// --- 例外边界落在原子块内部也能精确切分 ---
test('精确交集：/32 例外边界落在规则原子块内部，按单地址切分', () => {
  const rules = setupFull()
  const report = computeExemptions(
    rules,
    [ex({ ruleId: 'B', cidr: '10.0.0.10/32' })],
    NOW,
  )
  const re = report.byRule.get('B')!
  assert.equal(re.exemptedSize, 1 * 65536 * 2)
  assert.equal(re.remainingSize, 256 * 65536 * 2 - 65536 * 2)
  assert.equal(re.exemptedExample!.srcIp, '10.0.0.10')
})

// --- 例外范围超出遮蔽区域：只覆盖交集；全覆盖 → 全部豁免 ---
test('例外覆盖整个遮蔽区域 → 全部豁免，待处理为 0', () => {
  const rules = setupPartial()
  const report = computeExemptions(rules, [ex({ ruleId: 'B', cidr: '0.0.0.0/0' })], NOW)
  const re = report.byRule.get('B')!
  assert.equal(re.exemptedSize, 128 * 65536 * 2)
  assert.equal(re.remainingSize, 0)
  assert.equal(re.status, 'full')
  assert.equal(re.remainingExample, null)
  assert.deepEqual(re.remainingRegions, [])
})

// --- 例外与遮蔽区域无交集 ---
test('例外落在规则可达部分：生效但覆盖为 0，规则仍为无豁免', () => {
  const rules = setupPartial()
  const report = computeExemptions(rules, [ex({ ruleId: 'B', cidr: '10.0.0.128/25' })], NOW)
  const ev = report.evaluations[0]
  assert.equal(ev.status, 'active')
  assert.equal(ev.coveredCells, 0)
  assert.equal(ev.coveredSize, 0)
  const re = report.byRule.get('B')!
  assert.equal(re.exemptedSize, 0)
  assert.equal(re.status, 'none')
  assert.equal(re.coveringExceptions.length, 0)
})

// --- 问题类型匹配 ---
test('问题类型须与规则当前状态匹配，否则不适用', () => {
  const partial = setupPartial()
  // B 当前为部分遮蔽
  const mismatch = computeExemptions(
    partial,
    [ex({ ruleId: 'B', issueType: 'fully-shadowed', cidr: '10.0.0.0/25' })],
    NOW,
  )
  assert.equal(mismatch.evaluations[0].status, 'inactive')
  assert.match(mismatch.evaluations[0].reason!, /不符/)
  assert.equal(mismatch.byRule.get('B')!.exemptedSize, 0)

  const match = computeExemptions(
    partial,
    [ex({ ruleId: 'B', issueType: 'partial-shadowed', cidr: '10.0.0.0/25' })],
    NOW,
  )
  assert.equal(match.evaluations[0].status, 'active')

  // 完全遮蔽规则上登记部分遮蔽 → 不适用
  const fullMismatch = computeExemptions(
    setupFull(),
    [ex({ ruleId: 'B', issueType: 'partial-shadowed' })],
    NOW,
  )
  assert.equal(fullMismatch.evaluations[0].status, 'inactive')

  // 任意遮蔽问题同时匹配部分与完全遮蔽
  const anyOnFull = computeExemptions(
    setupFull(),
    [ex({ ruleId: 'B', issueType: 'any-shadow' })],
    NOW,
  )
  assert.equal(anyOnFull.evaluations[0].status, 'active')

  // 完全可达规则没有遮蔽区域 → 不适用
  const reachable = computeExemptions(
    [rule({ id: 'A', cidr: '10.0.0.0/25' })],
    [ex({ ruleId: 'A', issueType: 'any-shadow' })],
    NOW,
  )
  assert.equal(reachable.evaluations[0].status, 'inactive')
  assert.match(reachable.evaluations[0].reason!, /完全可达/)
})

// --- 目标规则缺失 / 停用 / 非法 ---
test('目标规则不存在、已停用、非法分别给出明确原因', () => {
  const rules = [
    rule({ id: 'A', cidr: '10.0.0.0/25' }),
    rule({ id: 'DIS', cidr: '10.1.0.0/16', enabled: false }),
    rule({ id: 'BAD', cidr: '10.0.0.1/24' }),
  ]
  const report = computeExemptions(
    rules,
    [
      ex({ id: 'e1', ruleId: 'GONE' }),
      ex({ id: 'e2', ruleId: 'DIS' }),
      ex({ id: 'e3', ruleId: 'BAD' }),
    ],
    NOW,
  )
  const [gone, dis, bad] = report.evaluations
  assert.equal(gone.status, 'inactive')
  assert.match(gone.reason!, /不存在/)
  assert.equal(dis.status, 'inactive')
  assert.match(dis.reason!, /已停用/)
  assert.equal(bad.status, 'inactive')
  assert.match(bad.reason!, /非法/)
  assert.equal(report.stats.inactive, 3)
})

// --- 多例外并集去重 ---
test('多条例外重叠时按并集去重，不重复计数', () => {
  const rules = setupPartial()
  const report = computeExemptions(
    rules,
    [
      ex({ id: 'e1', ruleId: 'B', cidr: '10.0.0.0/26' }),
      ex({ id: 'e2', ruleId: 'B', cidr: '10.0.0.0/25' }),
    ],
    NOW,
  )
  const re = report.byRule.get('B')!
  assert.equal(re.exemptedSize, 128 * 65536 * 2)
  assert.equal(re.status, 'full')
  assert.deepEqual(re.coveringExceptions, [0, 1])
  assert.equal(report.stats.totalExemptedSize, 128 * 65536 * 2)
})

// --- 规则编辑后重算 ---
test('规则编辑后交集自动变化（重算为纯函数）', () => {
  const exception = ex({ ruleId: 'B', cidr: '10.0.0.0/25' })
  const before = computeExemptions(setupPartial(), [exception], NOW)
  assert.equal(before.byRule.get('B')!.exemptedSize, 128 * 65536 * 2)

  // A 收缩为 /26：B 的遮蔽区域随之缩小，同一例外的交集同步缩小
  const edited = [
    rule({ id: 'A', name: 'A', cidr: '10.0.0.0/26' }),
    rule({ id: 'B', name: 'B', cidr: '10.0.0.0/24' }),
  ]
  const after = computeExemptions(edited, [exception], NOW)
  const re = after.byRule.get('B')!
  assert.equal(re.shadowedSize, 64 * 65536 * 2)
  assert.equal(re.exemptedSize, 64 * 65536 * 2)
  assert.equal(re.remainingSize, 0)
})

// --- 统计 ---
test('统计：各状态计数与已豁免 / 待处理空间合计', () => {
  const rules = setupPartial()
  const report = computeExemptions(
    rules,
    [
      ex({ ruleId: 'B', cidr: '10.0.0.0/26' }),
      ex({ ruleId: 'B', expiresAt: '2020-01-01T00:00' }),
      ex({ ruleId: 'B', cidr: '10.0.0.1/24' }),
      ex({ ruleId: 'GONE' }),
    ],
    NOW,
  )
  const s = report.stats
  assert.equal(s.total, 4)
  assert.equal(s.active, 1)
  assert.equal(s.expired, 1)
  assert.equal(s.invalid, 1)
  assert.equal(s.inactive, 1)
  assert.equal(s.totalExemptedSize, 64 * 65536 * 2)
  assert.equal(s.totalPendingSize, 64 * 65536 * 2)
  assert.equal(s.partiallyExemptedRules, 1)
  assert.equal(s.fullyExemptedRules, 0)
})

// --- 新建表单默认值 ---
test('新例外默认预填首条规则范围与 30 天到期', () => {
  const rules = [
    rule({ id: 'F', cidr: '10.0.0.0/8', portStart: '80', portEnd: '443', protocol: 'tcp' }),
  ]
  const input = newExceptionInput(rules, NOW)
  assert.equal(input.ruleId, 'F')
  assert.equal(input.cidr, '10.0.0.0/8')
  assert.equal(input.portStart, '80')
  assert.equal(input.portEnd, '443')
  assert.equal(input.protocol, 'TCP')
  assert.equal(input.issueType, 'any-shadow')
  assert.equal(Date.parse(input.expiresAt), NOW.getTime() + 30 * 24 * 3600 * 1000)
})

// --- 导入解析 ---
test('导入：裸数组 / exceptions 包装 / 容错与报错', () => {
  const ok = parseExceptionsJson(
    JSON.stringify([
      {
        ruleId: 'B',
        issueType: 'any-shadow',
        cidr: '10.0.0.0/24',
        portStart: 80,
        portEnd: 443,
        protocol: 'tcp',
        expiresAt: '2030-01-01T00:00',
        note: 'n',
      },
    ]),
  )
  assert.equal(ok.errors.length, 0)
  assert.equal(ok.exceptions.length, 1)
  assert.equal(ok.exceptions[0].protocol, 'TCP')
  assert.equal(ok.exceptions[0].portStart, 80)
  assert.ok(ok.exceptions[0].id)

  const wrapped = parseExceptionsJson('{"exceptions":[{"ruleId":"B"}]}')
  assert.equal(wrapped.exceptions.length, 1)
  assert.equal(wrapped.exceptions[0].ruleId, 'B')

  assert.match(parseExceptionsJson('{oops').errors[0], /JSON 解析失败/)
  assert.match(parseExceptionsJson('{"foo":1}').errors[0], /exceptions/)
  assert.match(parseExceptionsJson('42').errors[0], /数组或对象/)

  const mixed = parseExceptionsJson('[1, {"ruleId":"B"}]')
  assert.equal(mixed.exceptions.length, 1)
  assert.equal(mixed.errors.length, 1)
  assert.match(mixed.errors[0], /第 1 条/)
})

// --- 导出往返 ---
test('导出 JSON 可原样再导入（字段保留）', () => {
  const list = [
    ex({ id: 'keep-1', ruleId: 'B', note: '测试说明', issueType: 'fully-shadowed' }),
  ]
  const round = parseExceptionsJson(exportExceptions(list))
  assert.equal(round.errors.length, 0)
  assert.equal(round.exceptions.length, 1)
  assert.equal(round.exceptions[0].id, 'keep-1')
  assert.equal(round.exceptions[0].note, '测试说明')
  assert.equal(round.exceptions[0].issueType, 'fully-shadowed')
})

console.log(`\nexemption.test.ts: ${passed} 项用例全部通过`)
