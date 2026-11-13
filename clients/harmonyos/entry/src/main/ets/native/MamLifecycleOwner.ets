// Exactly-one MAM start/resume composition owner for the Harmony shell.
// The production instance is explicitly OFF until Connectivity E4 rollout
// evidence enables the existing off/observe/execute contract.

import { hilog } from '@kit.PerformanceAnalysisKit';

const TAG: string = 'MamLifecycleOwner';
const DOMAIN: number = 0x0001;

export type MamRolloutMode = 'off' | 'observe' | 'execute';
export const DEFAULT_MAM_ROLLOUT_MODE: MamRolloutMode = 'off';
export const MAM_PERIODIC_INTERVAL_MS: number = 15 * 60 * 1000;

export class MamLifecycleOwner {
  private started: boolean = false;
  private foreground: boolean = true;
  private inFlight: boolean = false;
  private pendingOpportunity: boolean = false;
  private timer: number = -1;
  private mode: MamRolloutMode;
  private checkin: () => Promise<void>;

  constructor(mode: MamRolloutMode, checkin: () => Promise<void>) {
    this.mode = mode;
    this.checkin = checkin;
  }

  start(): void {
    if (this.started) {
      return;
    }
    this.started = true;
    this.foreground = true;
    if (this.mode !== 'execute') {
      return;
    }
    this.requestOpportunity();
    this.timer = setInterval((): void => this.requestOpportunity(), MAM_PERIODIC_INTERVAL_MS);
  }

  pause(): void {
    if (this.started) {
      this.foreground = false;
    }
  }

  resume(): void {
    if (!this.started || this.foreground) {
      return;
    }
    this.foreground = true;
    this.requestOpportunity();
  }

  stop(): void {
    if (!this.started) {
      return;
    }
    this.started = false;
    this.foreground = false;
    this.pendingOpportunity = false;
    if (this.timer !== -1) {
      clearInterval(this.timer);
      this.timer = -1;
    }
  }

  private requestOpportunity(): void {
    if (!this.started || !this.foreground || this.mode !== 'execute') {
      return;
    }
    if (this.inFlight) {
      this.pendingOpportunity = true;
      return;
    }
    this.inFlight = true;
    this.checkin().catch((error: Error): void => {
      hilog.error(DOMAIN, TAG, `check-in failed: ${error.message}`);
    }).then((): void => {
      this.inFlight = false;
      if (this.pendingOpportunity && this.started && this.foreground) {
        this.pendingOpportunity = false;
        this.requestOpportunity();
      }
    });
  }
}

/** Process singleton linking EntryAbility lifecycle to MainPage's native MAM adapter. */
export class MamLifecycleComposition {
  private static owner: MamLifecycleOwner | null = null;

  static install(owner: MamLifecycleOwner): void {
    if (MamLifecycleComposition.owner === owner) {
      return;
    }
    MamLifecycleComposition.owner?.stop();
    MamLifecycleComposition.owner = owner;
    owner.start();
  }

  static uninstall(owner: MamLifecycleOwner): void {
    if (MamLifecycleComposition.owner !== owner) {
      return;
    }
    owner.stop();
    MamLifecycleComposition.owner = null;
  }

  static foreground(): void {
    MamLifecycleComposition.owner?.resume();
  }

  static background(): void {
    MamLifecycleComposition.owner?.pause();
  }

  static stop(): void {
    MamLifecycleComposition.owner?.stop();
    MamLifecycleComposition.owner = null;
  }
}
