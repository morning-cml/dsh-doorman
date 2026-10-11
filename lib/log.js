/**
 * Append-only JSON-lines decision log, one file per month
 * (`logs/decisions-YYYY-MM.jsonl`), continued in `-2`, `-3`… files once a
 * file grows past the size limit. Writing never throws: a broken disk must
 * not break dsh.
 */

import fs from 'node:fs'
import path from 'node:path'

/**
 * @param {object} options
 * @param {string} options.dir - the logs directory.
 * @param {() => Date} [options.now]
 * @param {() => number} [options.maxFileBytes]
 */
export function createLog({ dir, now = () => new Date(), maxFileBytes = () => 50 * 1024 * 1024 }) {
  let ready = false
  let current = null

  function fileFor(date) {
    const month = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`
    if (current !== null && current.month === month) {
      try {
        if (fs.statSync(current.file).size < maxFileBytes()) return current.file
      } catch {
        return current.file
      }
    }
    for (let part = 1; part < 1000; part += 1) {
      const file = path.join(dir, `decisions-${month}${part === 1 ? '' : `-${part}`}.jsonl`)
      let size = 0
      try { size = fs.statSync(file).size } catch { size = 0 }
      if (size < maxFileBytes()) {
        current = { month, file }
        return file
      }
    }
    return path.join(dir, `decisions-${month}-overflow.jsonl`)
  }

  /**
   * Write one event.
   * @param {string} event
   * @param {object} [data]
   */
  function write(event, data = {}) {
    try {
      if (!ready) {
        fs.mkdirSync(dir, { recursive: true })
        ready = true
      }
      const date = now()
      const line = JSON.stringify({ ts: date.toISOString(), event, ...data })
      fs.appendFileSync(fileFor(date), `${line}\n`, 'utf8')
    } catch {
      // The log is best effort; the approval flow never depends on it.
    }
  }

  return { write, dir }
}
