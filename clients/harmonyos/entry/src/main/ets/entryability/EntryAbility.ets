// EntryAbility — Main entry point for SetJoin Mail (Stage model)

import { UIAbility, Want, AbilityConstant } from '@kit.AbilityKit';
import { window } from '@kit.ArkUI';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { PushService } from '../common/PushService';
import { MamLifecycleComposition } from '../native/MamLifecycleOwner';

const TAG: string = 'EntryAbility';
const DOMAIN: number = 0x0001;

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, TAG, 'EntryAbility onCreate');

    // Fire-and-forget: HMS token fetch shouldn't block boot. Errors are
    // already caught+logged inside PushService.initialize; this .catch is
    // belt-and-suspenders against a rejected promise slipping past that.
    PushService.getInstance().initialize(this.context).catch((err: Error) => {
      hilog.error(DOMAIN, TAG, `PushService.initialize failed: ${err.message}`);
    });
  }

  onDestroy(): void {
    MamLifecycleComposition.stop();
    hilog.info(DOMAIN, TAG, 'EntryAbility onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    hilog.info(DOMAIN, TAG, 'onWindowStageCreate');

    // Load the server-config gate first; it auto-navigates to MainPage (the
    // ArkWeb host page) once a server address is persisted.
    windowStage.loadContent('pages/ServerConfigPage', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, TAG, `Failed to load ServerConfigPage: ${err.code}`);
        return;
      }
      hilog.info(DOMAIN, TAG, 'ServerConfigPage loaded successfully');
    });

    // Set window privacy mode (screenshots blocked) — defer to MAMEnforcer
    windowStage.getMainWindow().then((win: window.Window) => {
      // Initial transparency / liquid glass feel
      win.setWindowBackgroundColor('#F2F2F7');
    });
  }

  onWindowStageDestroy(): void {
    hilog.info(DOMAIN, TAG, 'onWindowStageDestroy');
  }

  onForeground(): void {
    MamLifecycleComposition.foreground();
    hilog.info(DOMAIN, TAG, 'onForeground');
  }

  onBackground(): void {
    MamLifecycleComposition.background();
    hilog.info(DOMAIN, TAG, 'onBackground');
  }
}
