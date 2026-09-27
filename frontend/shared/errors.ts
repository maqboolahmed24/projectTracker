/** Never render transport messages, server traces or customer content from errors. */
export function customerError(error:unknown):string {
  const code=typeof error==='object'&&error!==null&&'code'in error?String(error.code):error instanceof Error?error.message:'';
  if(/OFFLINE|NETWORK|fetch/i.test(code))return 'You appear to be offline. Reconnect, then try again. Your saved work is still here.';
  if(/PASSWORD|INVALID_CREDENTIALS|AUTH_FAILED|LOGIN_FAILED/.test(code))return 'That password did not work. Try again, or choose Forgot password.';
  if(/RATE_LIMIT|BUDGET/.test(code))return 'Please wait a moment before trying again.';
  if(/REAUTH_REQUIRED/.test(code))return 'Confirm your password to continue.';
  if(/AUTH_REQUIRED|LOGGED_OUT|SESSION_EXPIRED/.test(code))return 'Please sign in again to continue.';
  if(/CONFLICT|SECURITY_STATE_CHANGED|REVIEW_REQUIRED|STALE/.test(code))return 'Something has changed since you opened this. Refresh, review the latest version, and try again.';
  if(/EXPIRED/.test(code))return 'This invitation or request has expired. Ask an Owner for a new one.';
  if(/FORBIDDEN|DENIED|NOT_AUTHORIZED|NOT_FOUND/.test(code))return 'This is no longer available to you. Return to your workspace or ask an Owner for access.';
  if(/TRUST|FINGERPRINT|MISMATCH/.test(code))return 'These details do not match. Check them with the other person before continuing.';
  if(/UNSUPPORTED/.test(code))return 'This browser cannot open your workspace securely. Please use an up-to-date Chrome, Edge, Firefox or Safari browser with storage enabled.';
  if(/CANCELLED|CLOSED/.test(code))return 'The action was stopped. You can return and try again.';
  if(/INVALID|VALIDATION|Zod/.test(code))return 'Please check the information you entered and try again.';
  return 'We could not complete that just now. Your saved progress is safe. Please try again.';
}
