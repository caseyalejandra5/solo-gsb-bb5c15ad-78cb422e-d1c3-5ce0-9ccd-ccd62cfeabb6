import { Fragment, useRef, useState } from 'react'
import type { ChangeEvent } from 'react'
import type { RuleInput } from './audit/types'
import {
  ISSUE_TYPE_TEXT,
  ISSUE_TYPES,
  exportExceptions,
  formatDateTime,
  toLocalDateTimeInput,
} from './audit/exemption'
import type {
  ExceptionEvaluation,
  ExceptionInput,
  ExceptionStatus,
  ExemptionReport,
} from './audit/exemption'
import { validatePortRange } from './audit/engine'
import { parseCidrStrict } from './audit/iputil'
import { formatSize } from './format'

interface Props {
  rules: RuleInput[]
  exceptions: ExceptionInput[]
  report: ExemptionReport
  onPatch: (index: number, patch: Partial<ExceptionInput>) => void
  onRemove: (index: number) => void
  onAdd: () => void
  onImport: (text: string, mode: 'replace' | 'append') => string[]
  onClear: () => void
}

const STATUS_BADGE: Record<ExceptionStatus, { text: string; cls: string }> = {
  active: { text: '生效中', cls: 'reachable' },
  expired: { text: '已过期 · 不参与豁免', cls: 'partial-shadowed' },
  invalid: { text: '非法 · 不参与豁免', cls: 'invalid' },
  inactive: { text: '不适用 · 不参与豁免', cls: 'muted' },
}

/** 字段级红框提示（仅展示用途；权威判定以评估结果为准） */
function fieldFlags(ex: ExceptionInput): {
  cidrBad: boolean
  portBad: boolean
  expiresBad: boolean
} {
  let cidrBad = false
  if (!ex.cidr.trim()) cidrBad = true
  else {
    try {
      parseCidrStrict(ex.cidr)
    } catch {
      cidrBad = true
    }
  }
  const ports = validatePortRange(String(ex.portStart).trim(), String(ex.portEnd).trim())
  const expiresBad =
    !ex.expiresAt.trim() || Number.isNaN(Date.parse(ex.expiresAt.trim()))
  return { cidrBad, portBad: ports.errors.length > 0, expiresBad }
}

interface RowMessage {
  kind: 'error' | 'warn' | 'muted'
  text: string
}

function rowMessages(ev: ExceptionEvaluation | undefined, nowMs: number): RowMessage[] {
  if (!ev) return []
  if (ev.status === 'invalid') {
    return [
      ...ev.errors.map((e): RowMessage => ({ kind: 'error', text: e })),
      { kind: 'error', text: '该条目存在非法字段，不参与豁免。' },
    ]
  }
  if (ev.status === 'expired') {
    return [
      {
        kind: 'warn',
        text: `${ev.reason}（评估基准时间 ${formatDateTime(nowMs)}），不参与豁免。`,
      },
    ]
  }
  if (ev.status === 'inactive') {
    return [{ kind: 'muted', text: `${ev.reason}，不参与豁免。` }]
  }
  if (ev.status === 'active' && ev.coveredCells === 0) {
    return [
      { kind: 'warn', text: '与目标规则的实际遮蔽区域无交集，当前未豁免任何报文。' },
    ]
  }
  return []
}

const EXAMPLE_JSON = `[
  {
    "ruleId": "规则 id（可用「导出规则」查看）",
    "issueType": "any-shadow",
    "cidr": "10.0.0.0/25",
    "portStart": 0,
    "portEnd": 65535,
    "protocol": "ANY",
    "expiresAt": "2026-12-31T23:59",
    "note": "例外说明"
  }
]`

function ExceptionImportModal({
  onClose,
  onImport,
}: {
  onClose: () => void
  onImport: (text: string, mode: 'replace' | 'append') => string[]
}) {
  const [text, setText] = useState('')
  const [errors, setErrors] = useState<string[]>([])
  const fileRef = useRef<HTMLInputElement>(null)

  const doImport = (mode: 'replace' | 'append') => {
    const errs = onImport(text, mode)
    if (errs.length > 0) setErrors(errs)
    else onClose()
  }

  const readFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => setText(String(reader.result ?? ''))
    reader.readAsText(file)
    e.target.value = ''
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">导入审计例外（JSON）</div>
        <div className="modal-body">
          <div className="notice info" style={{ marginTop: 0 }}>
            支持数组 <span className="mono">[{`{...}`}]</span> 或
            <span className="mono"> {'{ exceptions: [...] }'}</span>。字段：
            <span className="mono">
              {' '}
              ruleId, issueType, cidr, portStart, portEnd, protocol, expiresAt, note
            </span>
            。非法 / 过期条目不会中断导入，会保留在清单中并标记为不参与豁免。
          </div>
          <div className="exception-import-file">
            <button onClick={() => fileRef.current?.click()}>选择本地 JSON 文件…</button>
            <span className="muted-text">或直接粘贴到下方文本框</span>
            <input
              ref={fileRef}
              type="file"
              accept=".json,application/json"
              style={{ display: 'none' }}
              onChange={readFile}
            />
          </div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={EXAMPLE_JSON}
            spellCheck={false}
          />
          {errors.length > 0 && (
            <div className="notice error" style={{ marginTop: 10 }}>
              {errors.map((e, i) => (
                <div key={i}>• {e}</div>
              ))}
            </div>
          )}
        </div>
        <div className="modal-footer">
          <button onClick={onClose}>取消</button>
          <button onClick={() => doImport('append')}>追加到现有例外</button>
          <button className="primary" onClick={() => doImport('replace')}>
            替换全部例外
          </button>
        </div>
      </div>
    </div>
  )
}

export function ExceptionPanel({
  rules,
  exceptions,
  report,
  onPatch,
  onRemove,
  onAdd,
  onImport,
  onClear,
}: Props) {
  const [showImport, setShowImport] = useState(false)
  const s = report.stats

  const doExport = () => {
    const blob = new Blob([exportExceptions(exceptions)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'audit-exceptions.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="panel exception-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
        <h2 style={{ margin: 0 }}>审计例外清单</h2>
        <span className="legend">
          为指定规则的遮蔽问题登记例外范围（CIDR × 端口区间 × 协议）与到期时间；
          仅生效中的条目与审计发现的实际遮蔽区域做精确交集并标记「已豁免」，其余仍为待处理
        </span>
        <div style={{ flex: 1 }} />
        <button
          className="primary"
          onClick={onAdd}
          disabled={rules.length === 0}
          title={rules.length === 0 ? '请先新增规则' : '登记一条新的审计例外'}
        >
          ＋ 登记例外
        </button>
        <button onClick={() => setShowImport(true)}>导入 JSON</button>
        <button onClick={doExport} disabled={exceptions.length === 0}>
          导出 JSON
        </button>
        <button
          className="danger ghost"
          disabled={exceptions.length === 0}
          onClick={() => {
            if (confirm('清空全部例外？')) onClear()
          }}
        >
          清空
        </button>
      </div>

      {exceptions.length === 0 ? (
        <div className="notice info" style={{ marginBottom: 0, marginTop: 12 }}>
          还没有登记例外。点击「登记例外」为指定规则的遮蔽问题登记豁免范围，
          或「导入 JSON」从本地文件恢复。豁免仅是标记，不改变审计结论。
        </div>
      ) : (
        <Fragment>
          <div className="stats" style={{ marginTop: 12 }}>
            <div className="stat-card ok">
              <div className="label">生效中</div>
              <div className="value">{s.active}</div>
            </div>
            <div className="stat-card warn">
              <div className="label">已过期（不参与）</div>
              <div className="value">{s.expired}</div>
            </div>
            <div className="stat-card danger">
              <div className="label">非法（不参与）</div>
              <div className="value">{s.invalid}</div>
            </div>
            <div className="stat-card">
              <div className="label">不适用（不参与）</div>
              <div className="value">{s.inactive}</div>
            </div>
            <div className="stat-card ok">
              <div className="label">已豁免报文空间</div>
              <div className="value" style={{ fontSize: 16 }}>
                {formatSize(s.totalExemptedSize)}
              </div>
              <div className="label">
                {s.fullyExemptedRules} 条全部豁免 / {s.partiallyExemptedRules} 条部分豁免
              </div>
            </div>
            <div className="stat-card warn">
              <div className="label">待处理报文空间</div>
              <div className="value" style={{ fontSize: 16 }}>
                {formatSize(s.totalPendingSize)}
              </div>
              <div className="label">各规则遮蔽区域合计</div>
            </div>
          </div>

          <div className="legend" style={{ marginBottom: 10 }}>
            评估基准时间 {formatDateTime(report.nowMs)}；规则或例外编辑后自动重算。
            非法 / 已过期 / 不适用的条目已明确标出，不参与豁免。
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="rule-table exception-table">
              <thead>
                <tr>
                  <th style={{ width: 34 }}>#</th>
                  <th style={{ minWidth: 150 }}>目标规则</th>
                  <th style={{ minWidth: 110 }}>问题类型</th>
                  <th style={{ minWidth: 130 }}>适用 CIDR</th>
                  <th style={{ minWidth: 150 }}>端口区间</th>
                  <th style={{ width: 84 }}>协议</th>
                  <th style={{ minWidth: 170 }}>到期时间</th>
                  <th style={{ minWidth: 130 }}>说明</th>
                  <th style={{ minWidth: 120 }}>状态</th>
                  <th style={{ width: 64 }}>操作</th>
                </tr>
              </thead>
              <tbody>
                {exceptions.map((ex, i) => {
                  const ev = report.evaluations[i]
                  const badge = ev ? STATUS_BADGE[ev.status] : STATUS_BADGE.invalid
                  const flags = fieldFlags(ex)
                  const invalid = ev?.status === 'invalid'
                  const expiresMs = Date.parse(ex.expiresAt)
                  const messages = rowMessages(ev, report.nowMs)
                  return (
                    <Fragment key={`${i}-${ex.id}`}>
                      <tr>
                        <td className="idx-cell">{i + 1}</td>
                        <td>
                          <select
                            value={ex.ruleId}
                            onChange={(e) => onPatch(i, { ruleId: e.target.value })}
                          >
                            {!rules.some((r) => r.id === ex.ruleId) && (
                              <option value={ex.ruleId}>
                                {ex.ruleId ? '（已删除或不存在的规则）' : '（未选择规则）'}
                              </option>
                            )}
                            {rules.map((r, ri) => (
                              <option key={r.id} value={r.id}>
                                #{ri + 1} {r.name.trim() || `规则 #${ri + 1}`}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td>
                          <select
                            value={ex.issueType}
                            onChange={(e) => onPatch(i, { issueType: e.target.value })}
                          >
                            {!ISSUE_TYPES.includes(
                              ex.issueType as (typeof ISSUE_TYPES)[number],
                            ) && (
                              <option value={ex.issueType}>
                                （非法：{ex.issueType || '空'}）
                              </option>
                            )}
                            {ISSUE_TYPES.map((t) => (
                              <option key={t} value={t}>
                                {ISSUE_TYPE_TEXT[t]}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td>
                          <input
                            className={invalid && flags.cidrBad ? 'invalid-field' : ''}
                            value={ex.cidr}
                            onChange={(e) => onPatch(i, { cidr: e.target.value })}
                            placeholder="10.0.0.0/8"
                            spellCheck={false}
                          />
                        </td>
                        <td>
                          <div className="port-cell">
                            <input
                              className={invalid && flags.portBad ? 'invalid-field' : ''}
                              value={ex.portStart}
                              onChange={(e) => onPatch(i, { portStart: e.target.value })}
                              placeholder="0"
                            />
                            <span className="muted-text">–</span>
                            <input
                              className={invalid && flags.portBad ? 'invalid-field' : ''}
                              value={ex.portEnd}
                              onChange={(e) => onPatch(i, { portEnd: e.target.value })}
                              placeholder="65535"
                            />
                          </div>
                        </td>
                        <td>
                          <select
                            value={ex.protocol.toUpperCase()}
                            onChange={(e) => onPatch(i, { protocol: e.target.value })}
                          >
                            {!['ANY', 'TCP', 'UDP'].includes(
                              ex.protocol.trim().toUpperCase(),
                            ) && <option value={ex.protocol}>（非法）</option>}
                            {['ANY', 'TCP', 'UDP'].map((p) => (
                              <option key={p} value={p}>
                                {p}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td>
                          <input
                            type="datetime-local"
                            className={invalid && flags.expiresBad ? 'invalid-field' : ''}
                            value={
                              Number.isNaN(expiresMs) ? '' : toLocalDateTimeInput(expiresMs)
                            }
                            onChange={(e) => onPatch(i, { expiresAt: e.target.value })}
                          />
                        </td>
                        <td>
                          <input
                            value={ex.note}
                            onChange={(e) => onPatch(i, { note: e.target.value })}
                            placeholder="例外说明（可选）"
                          />
                        </td>
                        <td>
                          <span className={`badge ${badge.cls}`}>{badge.text}</span>
                          {ev?.status === 'active' && (
                            <div className="exception-status-sub muted-text">
                              豁免 {formatSize(ev.coveredSize)}
                              <br />
                              {formatDateTime(ev.normalized!.expiresAtMs)} 到期
                            </div>
                          )}
                          {ev?.status === 'inactive' && ev.targetRuleIndex !== null && (
                            <div className="exception-status-sub muted-text">
                              目标 #{ev.targetRuleIndex + 1} {ev.targetRuleName}
                            </div>
                          )}
                        </td>
                        <td>
                          <div className="row-actions">
                            <button
                              className="danger"
                              title="删除该例外"
                              onClick={() => onRemove(i)}
                            >
                              删除
                            </button>
                          </div>
                        </td>
                      </tr>
                      {messages.length > 0 && (
                        <tr className="exception-msg-row">
                          <td colSpan={10}>
                            {messages.map((m, mi) => (
                              <div key={mi} className={`msg ${m.kind}`}>
                                • {m.text}
                              </div>
                            ))}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Fragment>
      )}

      {showImport && (
        <ExceptionImportModal onClose={() => setShowImport(false)} onImport={onImport} />
      )}
    </div>
  )
}
