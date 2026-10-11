/**
 * Rolling one-hour cap on model calls, so an agent stuck in a loop cannot run
 * up a bill. Past the cap every request simply goes to the user.
 */

const HOUR_MS = 60 * 60 * 1000

/**
 * @param {() => number} [now]
 */
export function createLimiter(now = () => Date.now()) {
  const stamps = []
  const prune = () => {
    const t = now()
    while (stamps.length > 0 && t - stamps[0] >= HOUR_MS) stamps.shift()
  }
  return {
    /**
     * Take one call from the budget.
     * @param {number} maxPerHour - 0 disables model calls.
     * @returns {boolean} whether the call may go ahead.
     */
    tryAcquire(maxPerHour) {
      prune()
      if (!(maxPerHour > 0) || stamps.length >= maxPerHour) return false
      stamps.push(now())
      return true
    },
    /** Calls made in the last hour. */
    used() {
      prune()
      return stamps.length
    },
  }
}
