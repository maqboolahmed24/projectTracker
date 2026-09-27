export const markSVG: string;

export interface LaunchOptions {
  /** Your app initialization promise. Omit to play a timed intro. */
  ready?: PromiseLike<unknown>;
  /** Optional app container; temporarily inert while the splash is visible. */
  appRoot?: HTMLElement;
  theme?: 'light' | 'dark' | 'auto';
  /** Minimum visible time including entrance, in milliseconds. Default 2850. */
  minDuration?: number;
  /** Hard removal deadline including asset loading, in milliseconds. Default 10000. */
  maxDuration?: number;
  /** Override when your bundler does not copy relative CSS assets. */
  stylesheetUrl?: string | URL;
  /** Visible page logo to receive the assembled mark. Unavailable targets fade. */
  logoTarget?: string;
}

export type LaunchResult = {
  reason: 'ready' | 'timeout' | 'error' | 'destroyed';
  error?: unknown;
};

export function mountUKDALaunch(options?: LaunchOptions): {
  /** Resolves after removal on every path; it does not report app readiness. */
  finished: Promise<LaunchResult>;
  /** Signal readiness early; minimum entrance time still applies. Idempotent. */
  finish(): void;
  /** Remove immediately and release resources. Idempotent. */
  destroy(): void;
};

export function animateMark(svg: SVGSVGElement, options?: {
  reducedMotion?: boolean;
}): { finished: Promise<void>; cancel(): void };
