// PushService — HMS Push Kit integration
// getToken() returns Promise<string> with 112-char token

import { pushService } from '@kit.PushKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { common } from '@kit.AbilityKit';

const TAG: string = 'PushService';
const DOMAIN: number = 0x0001;

// Typed interface for checkin token data
export interface PushCheckinData {
  platform: string;
  push_token: string;
  push_type: string;
}

export class PushService {
  private static instance: PushService;
  private token: string = '';
  private onMessageCallback: ((data: Object) => void) | null = null;
  private initialized: boolean = false;

  static getInstance(): PushService {
    if (!PushService.instance) {
      PushService.instance = new PushService();
    }
    return PushService.instance;
  }

  async initialize(context: common.Context): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      // Get push token — returns 112-char string via Promise
      this.token = await pushService.getToken();
      hilog.info(DOMAIN, TAG, `Push token obtained: length=${this.token.length}`);

      this.initialized = true;
    } catch (err) {
      const error: Error = err instanceof Error ? err : new Error(String(err));
      hilog.error(DOMAIN, TAG, `Push initialization failed: ${error.message}`);
    }
  }

  getToken(): string {
    return this.token;
  }

  setOnMessageCallback(callback: (data: Object) => void): void {
    this.onMessageCallback = callback;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  getTokenForCheckin(): PushCheckinData {
    return {
      platform: 'harmonyos',
      push_token: this.token,
      push_type: 'hms',
    };
  }
}
