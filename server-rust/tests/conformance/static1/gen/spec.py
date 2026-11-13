"""Single source for the F20/F22 + translate case table (#271). `python3 emit_rust.py`
writes bins/gateway/tests/static_oracle/cases.rs; `python3 emit_catalog.py` rewrites the
F20/F22/translate suites of route-catalog.json and flips their inventory entries ON."""
import json,sys
CASES=[]
def case(name,route,kind,uri,method="GET",auth="None",cfg="Default",forwarded=False,headers=(),body="",world=None,repeat=False,contract=False):
    """`contract`: no Go recording is possible (Go refuses to start); the case only proves the forward."""
    CASES.append(dict(name=name,route=route,kind=kind,uri=uri,method=method,auth=auth,cfg=cfg,forwarded=forwarded,headers=headers,body=body,world=world or {},repeat=repeat,contract=contract))
def std3(key,route,path,inv=None,extra=()):
    inv=inv or path
    case(f"{key}_success",f"GET {inv}","success",path)
    case(f"{key}_foreign",f"GET {inv}","cross-tenant",path,auth="Foreign")
    case(f"{key}_invalid",f"GET {inv}","invalid-input",path+"?x=%zz&format=%3Cscript%3E&domain=")
    case(f"{key}_head",f"GET {inv}","head",path,method="HEAD")
for key,path in [("yaml","/api/openapi.yaml"),("json","/api/openapi.json"),("docs","/api/docs"),("redoc","/api/redoc.standalone.js"),("logo","/api/logo.svg"),("font400","/api/fonts/ibm-plex-sans-400.woff2"),("font500","/api/fonts/ibm-plex-sans-500.woff2"),("cert_hint","/api/cert-hint"),("ready","/ready")]:
    std3(key,None,path)
# full spec (admin gated)
for key,path in [("full_yaml","/api/openapi.full.yaml"),("full_json","/api/openapi.full.json")]:
    r=f"GET {path}"
    case(f"{key}_success",r,"success",path,auth="ActorPerm")
    case(f"{key}_foreign",r,"cross-tenant",path,auth="Foreign")
    case(f"{key}_invalid",r,"invalid-input",path)
    case(f"{key}_admin_without_role",r,"admin-without-role",path,auth="ActorAdmin")
# downloads
case("downloads_success","GET /downloads","success","/downloads")
case("downloads_foreign","GET /downloads","cross-tenant","/downloads",auth="Foreign")
case("downloads_invalid","GET /downloads","invalid-input","/downloads?x=%zz")
case("downloads_head","GET /downloads","head","/downloads",method="HEAD")
case("platform_success","GET /downloads/{platform}","success","/downloads/linux-x86_64-deb")
case("platform_foreign","GET /downloads/{platform}","cross-tenant","/downloads/macos-arm64",auth="Foreign")
case("platform_invalid","GET /downloads/{platform}","invalid-input","/downloads/not-a-platform")
case("platform_head","GET /downloads/{platform}","head","/downloads/windows-x86_64",method="HEAD")
case("asset_success","GET /downloads/asset/{asset}","success","/downloads/asset/SetJoin_latest_linux-x86_64.deb")
case("asset_foreign","GET /downloads/asset/{asset}","cross-tenant","/downloads/asset/SetJoin_latest_macos-arm64.dmg",auth="Foreign")
case("asset_invalid","GET /downloads/asset/{asset}","invalid-input","/downloads/asset/..%2fx")
case("asset_dot","GET /downloads/asset/{asset}","dot-segment","/downloads/asset/.",forwarded=True)
case("asset_unicode","GET /downloads/asset/{asset}","non-ascii","/downloads/asset/%C3%A9%20x%3Fy")
case("asset_head","GET /downloads/asset/{asset}","head","/downloads/asset/SetJoin_latest_windows-arm64.msi",method="HEAD")
# favicon
case("favicon_success","GET /favicon.ico","success","/favicon.ico",cfg="Website")
case("favicon_foreign","GET /favicon.ico","cross-tenant","/favicon.ico",cfg="Website",auth="Foreign")
case("favicon_invalid","GET /favicon.ico","invalid-input","/favicon.ico?x=%zz",cfg="Website")
case("favicon_unconfigured","GET /favicon.ico","unconfigured","/favicon.ico")
# health
case("health_success","GET /health","success","/health")
case("health_foreign","GET /health","cross-tenant","/health",auth="Foreign")
case("health_invalid","GET /health","invalid-input","/health?x=%zz")
case("health_head","GET /health","head","/health",method="HEAD")
case("health_warn","GET /health","warn","/health",world=dict(health="warn"))
case("health_error","GET /health","error","/health",world=dict(health="error"))
# metrics
case("metrics_success","GET /metrics","success","/metrics",cfg="MetricsToken",headers=[("authorization","Bearer static1-metrics")])
case("metrics_foreign","GET /metrics","cross-tenant","/metrics",cfg="MetricsToken",auth="Foreign")
case("metrics_invalid","GET /metrics","invalid-input","/metrics",cfg="MetricsToken",headers=[("authorization","Bearer wrong")])
case("metrics_unset","GET /metrics","fail-closed","/metrics")
case("metrics_open","GET /metrics","unauthenticated-opt-in","/metrics",cfg="MetricsOpen")
# setjoin well-known
case("setjoin_success","GET /.well-known/setjoin","success","/.well-known/setjoin")
case("setjoin_foreign","GET /.well-known/setjoin","cross-tenant","/.well-known/setjoin",auth="Foreign")
case("setjoin_invalid","GET /.well-known/setjoin","invalid-input","/.well-known/setjoin?x=%zz")
case("setjoin_configured","GET /.well-known/setjoin","configured-profile","/.well-known/setjoin",cfg="Hybrid")
case("setjoin_head","GET /.well-known/setjoin","head","/.well-known/setjoin",method="HEAD")
# autoconfig
AC="/.well-known/autoconfig/mail/config-v1.1.xml"
case("autoconfig_success","GET "+AC,"success",AC,headers=[("host","{domain}")])
case("autoconfig_foreign","GET "+AC,"cross-tenant",AC,headers=[("host","unknown-static1.invalid")])
case("autoconfig_invalid","GET "+AC,"invalid-input",AC+"?x=%zz",headers=[("host","{DOMAIN}:99999")])
case("autoconfig_imap_plain","GET "+AC,"imap-starttls",AC,cfg="ImapPlain",headers=[("host","{domain}")])
case("autoconfig_head","GET "+AC,"head",AC,method="HEAD",headers=[("host","{domain}")])
# caldav / carddav
for key,path,tog in [("caldav","/.well-known/caldav","feature.caldav"),("carddav","/.well-known/carddav","feature.carddav")]:
    r="GET "+path
    case(f"{key}_success",r,"success",path,world=dict(toggles=[(tog,True)]))
    case(f"{key}_foreign",r,"cross-tenant",path,auth="Foreign",world=dict(toggles=[(tog,True)]))
    case(f"{key}_invalid",r,"invalid-input",path+"?x=%zz",world=dict(toggles=[(tog,True)]))
    case(f"{key}_disabled",r,"disabled",path,world=dict(toggles=[(tog,False)]))
    case(f"{key}_head",r,"head",path,method="HEAD",world=dict(toggles=[(tog,True)]))
# discover
case("discover_success","GET /api/discover","success","/api/discover?domain=nonexistent.invalid")
case("discover_foreign","GET /api/discover","cross-tenant","/api/discover?domain=nonexistent.invalid",auth="Foreign")
case("discover_invalid","GET /api/discover","invalid-input","/api/discover")
case("discover_empty","GET /api/discover","empty-domain","/api/discover?domain=")
# telemetry
case("telemetry_success","POST /telemetry","success","/api/telemetry",method="POST",body='{"device_id":1,"app_version":"1.0"}',headers=[("content-type","application/json")])
case("telemetry_foreign","POST /telemetry","cross-tenant","/api/telemetry",method="POST",auth="Foreign",body='{"device_id":{foreign_user}}',headers=[("content-type","application/json")])
case("telemetry_invalid","POST /telemetry","invalid-input","/api/telemetry",method="POST",body='{',headers=[("content-type","application/json")])
case("telemetry_enabled_unproven","POST /telemetry","enabled-device-proof","/api/telemetry",method="POST",body='{"device_id":1}',headers=[("content-type","application/json")],world=dict(toggles=[("device_telemetry",True)]))
case("telemetry_enabled_invalid","POST /telemetry","enabled-invalid","/api/telemetry",method="POST",body='{',headers=[("content-type","application/json")],world=dict(toggles=[("device_telemetry",True)]))
# assist
J=[("content-type","application/json")]
GOOD='{"messages":[{"role":"user","content":"Say hi"},{"role":"system","content":"downgraded"}],"context":"compose\\nreply","locale":"fr"}'
ON=dict(assist=True,provider="Ok")
case("assist_success","POST /assist/complete","success","/api/assist/complete",method="POST",auth="Actor",headers=J,body=GOOD,world=ON)
case("assist_foreign","POST /assist/complete","cross-tenant","/api/assist/complete",method="POST",auth="Foreign",headers=J,body=GOOD,world=ON)
case("assist_invalid","POST /assist/complete","invalid-input","/api/assist/complete",method="POST",auth="Actor",headers=J,body='{"messages":[]}',world=ON)
case("assist_disabled","POST /assist/complete","disabled","/api/assist/complete",method="POST",auth="Actor",headers=J,body=GOOD,world=dict(assist=False,provider="Ok"))
case("assist_bad_json","POST /assist/complete","bad-json","/api/assist/complete",method="POST",auth="Actor",headers=J,body='{"messages":',world=ON)
case("assist_trailing","POST /assist/complete","trailing-json","/api/assist/complete",method="POST",auth="Actor",headers=J,body='{"messages":[{"role":"user","content":"x"}]} {}',world=ON)
case("assist_role","POST /assist/complete","invalid-role","/api/assist/complete",method="POST",auth="Actor",headers=J,body='{"messages":[{"role":"tool","content":"x"}]}',world=ON)
case("assist_case_fold","POST /assist/complete","case-folded-keys","/api/assist/complete",method="POST",auth="Actor",headers=J,body='{"MESSAGES":[{"ROLE":"user","Content":"folded"}],"Context":null}',world=ON)
case("assist_unconfigured","POST /assist/complete","unconfigured","/api/assist/complete",method="POST",auth="Actor",headers=J,body=GOOD,world=dict(assist=True,provider="None"))
case("assist_bad_url","POST /assist/complete","bad-provider-url","/api/assist/complete",method="POST",auth="Actor",headers=J,body=GOOD,world=dict(assist=True,provider="BadUrl"))
case("assist_upstream_error","POST /assist/complete","provider-error","/api/assist/complete",method="POST",auth="Actor",headers=J,body=GOOD,world=dict(assist=True,provider="Fail"))
case("assist_no_choices","POST /assist/complete","provider-no-choices","/api/assist/complete",method="POST",auth="Actor",headers=J,body=GOOD,world=dict(assist=True,provider="Empty"))
case("assist_sealed_key","POST /assist/complete","sealed-api-key","/api/assist/complete",method="POST",auth="Actor",headers=J,body=GOOD,world=dict(assist=True,provider="Sealed"))
case("assist_anonymous","POST /assist/complete","unauthenticated","/api/assist/complete",method="POST",headers=J,body=GOOD,world=ON,forwarded=True)
case("stream_success","POST /assist/stream","success","/api/assist/stream",method="POST",auth="Actor",headers=J,body="{}",world=ON)
case("stream_foreign","POST /assist/stream","cross-tenant","/api/assist/stream",method="POST",auth="Foreign",headers=J,body="{}",world=ON)
case("stream_invalid","POST /assist/stream","invalid-input","/api/assist/stream",method="POST",headers=J,body="{",forwarded=True)
case("stream_locale","POST /assist/stream","accept-language","/api/assist/stream",method="POST",auth="Actor",headers=J+[("accept-language","fr-CA,en;q=0.5")],body="{}")
# translate
T="POST /chat/messages/{id}/translate"
TU="/api/chat/messages/{message}/translate"
TB='{"targetLocale":"fr","userId":0}'
CH=dict(chat=True,assist=True,provider="Ok",compliance=True)
case("translate_success",T,"success",TU,method="POST",auth="Actor",headers=J,body=TB,world=CH)
case("translate_repeat",T,"repeat",TU,method="POST",auth="Actor",headers=J,body=TB,world=CH,repeat=True)
case("translate_foreign",T,"cross-tenant",TU,method="POST",auth="Foreign",headers=J,body=TB,world=CH)
case("translate_invalid",T,"invalid-input",TU,method="POST",auth="Actor",headers=J,body="{",world=CH)
case("translate_no_locale",T,"missing-locale",TU,method="POST",auth="Actor",headers=J,body="{}",world=CH)
case("translate_assist_off",T,"assist-disabled",TU,method="POST",auth="Actor",headers=J,body=TB,world=dict(chat=True,assist=False,provider="Ok"))
case("translate_unconfigured",T,"unconfigured",TU,method="POST",auth="Actor",headers=J,body=TB,world=dict(chat=True,assist=True,provider="None"))
case("translate_provider_error",T,"provider-error",TU,method="POST",auth="Actor",headers=J,body=TB,world=dict(chat=True,assist=True,provider="Fail",compliance=True))
case("translate_no_audit",T,"compliance-off",TU,method="POST",auth="Actor",headers=J,body=TB,world=dict(chat=True,assist=True,provider="Ok"))
case("translate_unknown_message",T,"unknown-message","/api/chat/messages/999999999/translate",method="POST",auth="Actor",headers=J,body=TB,world=CH)
case("translate_bad_id",T,"bad-id","/api/chat/messages/abc/translate",method="POST",auth="Actor",headers=J,body=TB,world=CH)
case("translate_chat_off",T,"chat-disabled","/api/chat/messages/1/translate",method="POST",auth="Actor",headers=J,body=TB,world=dict(chat=False,assist=True,provider="Ok"))
case("translate_sealed_key",T,"sealed-api-key",TU,method="POST",auth="Actor",headers=J,body=TB,world=dict(chat=True,assist=True,provider="Sealed"))
GOLDEN_DIR="server-rust/tests/conformance/static1/goldens"
def golden(c): return c["name"].replace("_","-")+".json"

# STATIC2: device-proof branch (independent from the default-OFF surface).
case("telemetry_proof_success","POST /telemetry device-proof","success","/api/telemetry",method="POST",headers=J,body='{"device_id":{device},"app_version":"1.0","os_version":"test","crash_count":2,"uptime_hours":3,"feature_usage":{"search":4}}',world=dict(telemetry="valid",toggles=[("device_telemetry",True)]))

case("telemetry_proof_legacy_bad_mac","POST /telemetry device-proof","legacy-invalid-hmac","/api/telemetry",method="POST",headers=J,body='{"device_id":{device}}',world=dict(telemetry="legacy-bad-mac",toggles=[("device_telemetry",True)]))

case("telemetry_proof_foreign","POST /telemetry device-proof","cross-tenant","/api/telemetry",method="POST",headers=J,body='{"device_id":{foreign_device}}',world=dict(telemetry="foreign",toggles=[("device_telemetry",True)]))

case("telemetry_proof_invalid","POST /telemetry device-proof","invalid-input","/api/telemetry",method="POST",headers=J,body='{"device_id":{device},"crash_count":"bad"}',world=dict(telemetry="valid",toggles=[("device_telemetry",True)]))

case("telemetry_proof_repeat","POST /telemetry device-proof","repeat","/api/telemetry",method="POST",headers=J,body='{"device_id":{device}}',world=dict(telemetry="valid",toggles=[("device_telemetry",True)]),repeat=True)

# Named qualification of the unchanged OFF branch; original recordings stay immutable.
case("telemetry_off_success","POST /telemetry toggle-off","success","/api/telemetry",method="POST",headers=J,body='{"device_id":1}',world=dict(toggles=[("device_telemetry",False)]))
case("telemetry_off_foreign","POST /telemetry toggle-off","cross-tenant","/api/telemetry",method="POST",auth="Foreign",headers=J,body='{"device_id":{foreign_user}}',world=dict(toggles=[("device_telemetry",False)]))
case("telemetry_off_invalid","POST /telemetry toggle-off","invalid-input","/api/telemetry",method="POST",headers=J,body='{',world=dict(toggles=[("device_telemetry",False)]))

case("telemetry_proof_legacy_valid","POST /telemetry device-proof","legacy-valid-hmac","/api/telemetry",method="POST",headers=J,body='{"device_id":{device}}',world=dict(telemetry="legacy-valid",toggles=[("device_telemetry",True)]))
case("telemetry_proof_body_mismatch","POST /telemetry device-proof","body-digest-mismatch","/api/telemetry",method="POST",headers=J,body='{"device_id":{device}}',world=dict(telemetry="body-mismatch",toggles=[("device_telemetry",True)]))

if __name__=="__main__":
    json.dump(CASES,open("cases.json","w"),indent=1)
    print(len(CASES))
