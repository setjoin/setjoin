# Push Kit - pushService API Reference
# Source: developer.huawei.com (2026-06-02)
# API Version: 5.0.0(12)+, HarmonyOS 6.1.1 (API 24)

## Module Import
import { pushService } from '@kit.PushKit';

## Key APIs
- getToken(): Promise<string> — 112-char token, API 4.0.0(10)
- getToken(callback: AsyncCallback<string>): void
- deleteToken(): Promise<void>
- deleteToken(callback: AsyncCallback<void>): void
- bindAppProfileId(appProfileType, appProfileId): Promise<void>
- unbindAppProfileId(appProfileId): Promise<void>
- receiveMessage(pushType, ability, onMessage): void
- on('tokenUpdate', ability, callback): void  (wearable only, API 5.1.0(18))
- off('tokenUpdate', callback?): void
- on('distributedMessageReceive', callee, callback): void  (API 6.0.0(20))
- off('distributedMessageReceive', callback?): void

## PushType (API 5.0.2(14))
- 'DEFAULT' — notification message
- 'IM' — text-to-speech message
- 'VoIP' — in-app call message
- 'BACKGROUND' — background message
- 'EMERGENCY' — emergency event message

## Error Codes
401, 1000900001, 1000900008, 1000900009, 1000900010, 1000900011, 1000900012, 1000900013, 1000900014, 1000900015, 1000900016, 1000900031

## NAPI Development Specifications
- napi_get_cb_info: argv must be >= argc when argv is not nullptr
- napi_open_handle_scope / napi_close_handle_scope for lifecycle
- napi_env bound to single engine instance (no cross-instance access)
- uv_queue_work requires napi_handle_scope for callback napi_value lifecycle
- napi_wrap: use napi_remove_wrap when result parameter is non-null
- ArrayBuffer preferred over JSArray for value-type data (3.6us vs 1566us)
- Module registration: static nm_register_func, unique module name, .nm_modname must match .so filename (case-sensitive)
