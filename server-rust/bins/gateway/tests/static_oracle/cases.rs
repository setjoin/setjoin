// GENERATED case table (see tests/conformance/static1/README.md). Do not hand-edit.
// included at the root of tests/static_recorded.rs

pub fn cases() -> Vec<Case> {
    vec![
        Case{name:"yaml_success",route:"GET /api/openapi.yaml",kind:"success",method:"GET",uri:"/api/openapi.yaml",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"yaml_foreign",route:"GET /api/openapi.yaml",kind:"cross-tenant",method:"GET",uri:"/api/openapi.yaml",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"yaml_invalid",route:"GET /api/openapi.yaml",kind:"invalid-input",method:"GET",uri:"/api/openapi.yaml?x=%zz&format=%3Cscript%3E&domain=",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"yaml_head",route:"GET /api/openapi.yaml",kind:"head",method:"HEAD",uri:"/api/openapi.yaml",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"json_success",route:"GET /api/openapi.json",kind:"success",method:"GET",uri:"/api/openapi.json",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"json_foreign",route:"GET /api/openapi.json",kind:"cross-tenant",method:"GET",uri:"/api/openapi.json",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"json_invalid",route:"GET /api/openapi.json",kind:"invalid-input",method:"GET",uri:"/api/openapi.json?x=%zz&format=%3Cscript%3E&domain=",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"json_head",route:"GET /api/openapi.json",kind:"head",method:"HEAD",uri:"/api/openapi.json",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"docs_success",route:"GET /api/docs",kind:"success",method:"GET",uri:"/api/docs",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"docs_foreign",route:"GET /api/docs",kind:"cross-tenant",method:"GET",uri:"/api/docs",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"docs_invalid",route:"GET /api/docs",kind:"invalid-input",method:"GET",uri:"/api/docs?x=%zz&format=%3Cscript%3E&domain=",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"docs_head",route:"GET /api/docs",kind:"head",method:"HEAD",uri:"/api/docs",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"redoc_success",route:"GET /api/redoc.standalone.js",kind:"success",method:"GET",uri:"/api/redoc.standalone.js",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"redoc_foreign",route:"GET /api/redoc.standalone.js",kind:"cross-tenant",method:"GET",uri:"/api/redoc.standalone.js",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"redoc_invalid",route:"GET /api/redoc.standalone.js",kind:"invalid-input",method:"GET",uri:"/api/redoc.standalone.js?x=%zz&format=%3Cscript%3E&domain=",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"redoc_head",route:"GET /api/redoc.standalone.js",kind:"head",method:"HEAD",uri:"/api/redoc.standalone.js",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"logo_success",route:"GET /api/logo.svg",kind:"success",method:"GET",uri:"/api/logo.svg",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"logo_foreign",route:"GET /api/logo.svg",kind:"cross-tenant",method:"GET",uri:"/api/logo.svg",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"logo_invalid",route:"GET /api/logo.svg",kind:"invalid-input",method:"GET",uri:"/api/logo.svg?x=%zz&format=%3Cscript%3E&domain=",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"logo_head",route:"GET /api/logo.svg",kind:"head",method:"HEAD",uri:"/api/logo.svg",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"font400_success",route:"GET /api/fonts/ibm-plex-sans-400.woff2",kind:"success",method:"GET",uri:"/api/fonts/ibm-plex-sans-400.woff2",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"font400_foreign",route:"GET /api/fonts/ibm-plex-sans-400.woff2",kind:"cross-tenant",method:"GET",uri:"/api/fonts/ibm-plex-sans-400.woff2",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"font400_invalid",route:"GET /api/fonts/ibm-plex-sans-400.woff2",kind:"invalid-input",method:"GET",uri:"/api/fonts/ibm-plex-sans-400.woff2?x=%zz&format=%3Cscript%3E&domain=",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"font400_head",route:"GET /api/fonts/ibm-plex-sans-400.woff2",kind:"head",method:"HEAD",uri:"/api/fonts/ibm-plex-sans-400.woff2",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"font500_success",route:"GET /api/fonts/ibm-plex-sans-500.woff2",kind:"success",method:"GET",uri:"/api/fonts/ibm-plex-sans-500.woff2",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"font500_foreign",route:"GET /api/fonts/ibm-plex-sans-500.woff2",kind:"cross-tenant",method:"GET",uri:"/api/fonts/ibm-plex-sans-500.woff2",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"font500_invalid",route:"GET /api/fonts/ibm-plex-sans-500.woff2",kind:"invalid-input",method:"GET",uri:"/api/fonts/ibm-plex-sans-500.woff2?x=%zz&format=%3Cscript%3E&domain=",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"font500_head",route:"GET /api/fonts/ibm-plex-sans-500.woff2",kind:"head",method:"HEAD",uri:"/api/fonts/ibm-plex-sans-500.woff2",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"cert_hint_success",route:"GET /api/cert-hint",kind:"success",method:"GET",uri:"/api/cert-hint",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"cert_hint_foreign",route:"GET /api/cert-hint",kind:"cross-tenant",method:"GET",uri:"/api/cert-hint",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"cert_hint_invalid",route:"GET /api/cert-hint",kind:"invalid-input",method:"GET",uri:"/api/cert-hint?x=%zz&format=%3Cscript%3E&domain=",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"cert_hint_head",route:"GET /api/cert-hint",kind:"head",method:"HEAD",uri:"/api/cert-hint",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"ready_success",route:"GET /ready",kind:"success",method:"GET",uri:"/ready",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"ready_foreign",route:"GET /ready",kind:"cross-tenant",method:"GET",uri:"/ready",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"ready_invalid",route:"GET /ready",kind:"invalid-input",method:"GET",uri:"/ready?x=%zz&format=%3Cscript%3E&domain=",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"ready_head",route:"GET /ready",kind:"head",method:"HEAD",uri:"/ready",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"full_yaml_success",route:"GET /api/openapi.full.yaml",kind:"success",method:"GET",uri:"/api/openapi.full.yaml",headers:vec![],body:"",auth:Auth::ActorPerm,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"full_yaml_foreign",route:"GET /api/openapi.full.yaml",kind:"cross-tenant",method:"GET",uri:"/api/openapi.full.yaml",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"full_yaml_invalid",route:"GET /api/openapi.full.yaml",kind:"invalid-input",method:"GET",uri:"/api/openapi.full.yaml",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"full_yaml_admin_without_role",route:"GET /api/openapi.full.yaml",kind:"admin-without-role",method:"GET",uri:"/api/openapi.full.yaml",headers:vec![],body:"",auth:Auth::ActorAdmin,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"full_json_success",route:"GET /api/openapi.full.json",kind:"success",method:"GET",uri:"/api/openapi.full.json",headers:vec![],body:"",auth:Auth::ActorPerm,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"full_json_foreign",route:"GET /api/openapi.full.json",kind:"cross-tenant",method:"GET",uri:"/api/openapi.full.json",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"full_json_invalid",route:"GET /api/openapi.full.json",kind:"invalid-input",method:"GET",uri:"/api/openapi.full.json",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"full_json_admin_without_role",route:"GET /api/openapi.full.json",kind:"admin-without-role",method:"GET",uri:"/api/openapi.full.json",headers:vec![],body:"",auth:Auth::ActorAdmin,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"downloads_success",route:"GET /downloads",kind:"success",method:"GET",uri:"/downloads",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"downloads_foreign",route:"GET /downloads",kind:"cross-tenant",method:"GET",uri:"/downloads",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"downloads_invalid",route:"GET /downloads",kind:"invalid-input",method:"GET",uri:"/downloads?x=%zz",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"downloads_head",route:"GET /downloads",kind:"head",method:"HEAD",uri:"/downloads",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"platform_success",route:"GET /downloads/{platform}",kind:"success",method:"GET",uri:"/downloads/linux-x86_64-deb",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"platform_foreign",route:"GET /downloads/{platform}",kind:"cross-tenant",method:"GET",uri:"/downloads/macos-arm64",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"platform_invalid",route:"GET /downloads/{platform}",kind:"invalid-input",method:"GET",uri:"/downloads/not-a-platform",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"platform_head",route:"GET /downloads/{platform}",kind:"head",method:"HEAD",uri:"/downloads/windows-x86_64",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"asset_success",route:"GET /downloads/asset/{asset}",kind:"success",method:"GET",uri:"/downloads/asset/SetJoin_latest_linux-x86_64.deb",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"asset_foreign",route:"GET /downloads/asset/{asset}",kind:"cross-tenant",method:"GET",uri:"/downloads/asset/SetJoin_latest_macos-arm64.dmg",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"asset_invalid",route:"GET /downloads/asset/{asset}",kind:"invalid-input",method:"GET",uri:"/downloads/asset/..%2fx",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"asset_dot",route:"GET /downloads/asset/{asset}",kind:"dot-segment",method:"GET",uri:"/downloads/asset/.",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:true,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"asset_unicode",route:"GET /downloads/asset/{asset}",kind:"non-ascii",method:"GET",uri:"/downloads/asset/%C3%A9%20x%3Fy",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"asset_head",route:"GET /downloads/asset/{asset}",kind:"head",method:"HEAD",uri:"/downloads/asset/SetJoin_latest_windows-arm64.msi",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"favicon_success",route:"GET /favicon.ico",kind:"success",method:"GET",uri:"/favicon.ico",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Website,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"favicon_foreign",route:"GET /favicon.ico",kind:"cross-tenant",method:"GET",uri:"/favicon.ico",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Website,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"favicon_invalid",route:"GET /favicon.ico",kind:"invalid-input",method:"GET",uri:"/favicon.ico?x=%zz",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Website,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"favicon_unconfigured",route:"GET /favicon.ico",kind:"unconfigured",method:"GET",uri:"/favicon.ico",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"health_success",route:"GET /health",kind:"success",method:"GET",uri:"/health",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"health_foreign",route:"GET /health",kind:"cross-tenant",method:"GET",uri:"/health",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"health_invalid",route:"GET /health",kind:"invalid-input",method:"GET",uri:"/health?x=%zz",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"health_head",route:"GET /health",kind:"head",method:"HEAD",uri:"/health",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"health_warn",route:"GET /health",kind:"warn",method:"GET",uri:"/health",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:Some("warn"),telemetry:None}},
        Case{name:"health_error",route:"GET /health",kind:"error",method:"GET",uri:"/health",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:Some("error"),telemetry:None}},
        Case{name:"metrics_success",route:"GET /metrics",kind:"success",method:"GET",uri:"/metrics",headers:vec![("authorization","Bearer static1-metrics")],body:"",auth:Auth::None,cfg:Cfg::MetricsToken,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"metrics_foreign",route:"GET /metrics",kind:"cross-tenant",method:"GET",uri:"/metrics",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::MetricsToken,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"metrics_invalid",route:"GET /metrics",kind:"invalid-input",method:"GET",uri:"/metrics",headers:vec![("authorization","Bearer wrong")],body:"",auth:Auth::None,cfg:Cfg::MetricsToken,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"metrics_unset",route:"GET /metrics",kind:"fail-closed",method:"GET",uri:"/metrics",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"metrics_open",route:"GET /metrics",kind:"unauthenticated-opt-in",method:"GET",uri:"/metrics",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::MetricsOpen,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"setjoin_success",route:"GET /.well-known/setjoin",kind:"success",method:"GET",uri:"/.well-known/setjoin",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"setjoin_foreign",route:"GET /.well-known/setjoin",kind:"cross-tenant",method:"GET",uri:"/.well-known/setjoin",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"setjoin_invalid",route:"GET /.well-known/setjoin",kind:"invalid-input",method:"GET",uri:"/.well-known/setjoin?x=%zz",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"setjoin_configured",route:"GET /.well-known/setjoin",kind:"configured-profile",method:"GET",uri:"/.well-known/setjoin",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Hybrid,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"setjoin_head",route:"GET /.well-known/setjoin",kind:"head",method:"HEAD",uri:"/.well-known/setjoin",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"autoconfig_success",route:"GET /.well-known/autoconfig/mail/config-v1.1.xml",kind:"success",method:"GET",uri:"/.well-known/autoconfig/mail/config-v1.1.xml",headers:vec![("host","{domain}")],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"autoconfig_foreign",route:"GET /.well-known/autoconfig/mail/config-v1.1.xml",kind:"cross-tenant",method:"GET",uri:"/.well-known/autoconfig/mail/config-v1.1.xml",headers:vec![("host","unknown-static1.invalid")],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"autoconfig_invalid",route:"GET /.well-known/autoconfig/mail/config-v1.1.xml",kind:"invalid-input",method:"GET",uri:"/.well-known/autoconfig/mail/config-v1.1.xml?x=%zz",headers:vec![("host","{DOMAIN}:99999")],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"autoconfig_imap_plain",route:"GET /.well-known/autoconfig/mail/config-v1.1.xml",kind:"imap-starttls",method:"GET",uri:"/.well-known/autoconfig/mail/config-v1.1.xml",headers:vec![("host","{domain}")],body:"",auth:Auth::None,cfg:Cfg::ImapPlain,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"autoconfig_head",route:"GET /.well-known/autoconfig/mail/config-v1.1.xml",kind:"head",method:"HEAD",uri:"/.well-known/autoconfig/mail/config-v1.1.xml",headers:vec![("host","{domain}")],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"caldav_success",route:"GET /.well-known/caldav",kind:"success",method:"GET",uri:"/.well-known/caldav",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("feature.caldav",true)],health:None,telemetry:None}},
        Case{name:"caldav_foreign",route:"GET /.well-known/caldav",kind:"cross-tenant",method:"GET",uri:"/.well-known/caldav",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("feature.caldav",true)],health:None,telemetry:None}},
        Case{name:"caldav_invalid",route:"GET /.well-known/caldav",kind:"invalid-input",method:"GET",uri:"/.well-known/caldav?x=%zz",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("feature.caldav",true)],health:None,telemetry:None}},
        Case{name:"caldav_disabled",route:"GET /.well-known/caldav",kind:"disabled",method:"GET",uri:"/.well-known/caldav",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("feature.caldav",false)],health:None,telemetry:None}},
        Case{name:"caldav_head",route:"GET /.well-known/caldav",kind:"head",method:"HEAD",uri:"/.well-known/caldav",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("feature.caldav",true)],health:None,telemetry:None}},
        Case{name:"carddav_success",route:"GET /.well-known/carddav",kind:"success",method:"GET",uri:"/.well-known/carddav",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("feature.carddav",true)],health:None,telemetry:None}},
        Case{name:"carddav_foreign",route:"GET /.well-known/carddav",kind:"cross-tenant",method:"GET",uri:"/.well-known/carddav",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("feature.carddav",true)],health:None,telemetry:None}},
        Case{name:"carddav_invalid",route:"GET /.well-known/carddav",kind:"invalid-input",method:"GET",uri:"/.well-known/carddav?x=%zz",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("feature.carddav",true)],health:None,telemetry:None}},
        Case{name:"carddav_disabled",route:"GET /.well-known/carddav",kind:"disabled",method:"GET",uri:"/.well-known/carddav",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("feature.carddav",false)],health:None,telemetry:None}},
        Case{name:"carddav_head",route:"GET /.well-known/carddav",kind:"head",method:"HEAD",uri:"/.well-known/carddav",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("feature.carddav",true)],health:None,telemetry:None}},
        Case{name:"discover_success",route:"GET /api/discover",kind:"success",method:"GET",uri:"/api/discover?domain=nonexistent.invalid",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"discover_foreign",route:"GET /api/discover",kind:"cross-tenant",method:"GET",uri:"/api/discover?domain=nonexistent.invalid",headers:vec![],body:"",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"discover_invalid",route:"GET /api/discover",kind:"invalid-input",method:"GET",uri:"/api/discover",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"discover_empty",route:"GET /api/discover",kind:"empty-domain",method:"GET",uri:"/api/discover?domain=",headers:vec![],body:"",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"telemetry_success",route:"POST /telemetry",kind:"success",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":1,\"app_version\":\"1.0\"}",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"telemetry_foreign",route:"POST /telemetry",kind:"cross-tenant",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":{foreign_user}}",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"telemetry_invalid",route:"POST /telemetry",kind:"invalid-input",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"telemetry_enabled_unproven",route:"POST /telemetry",kind:"enabled-device-proof",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":1}",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",true)],health:None,telemetry:None}},
        Case{name:"telemetry_enabled_invalid",route:"POST /telemetry",kind:"enabled-invalid",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",true)],health:None,telemetry:None}},
        Case{name:"assist_success",route:"POST /assist/complete",kind:"success",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"},{\"role\":\"system\",\"content\":\"downgraded\"}],\"context\":\"compose\\nreply\",\"locale\":\"fr\"}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_foreign",route:"POST /assist/complete",kind:"cross-tenant",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"},{\"role\":\"system\",\"content\":\"downgraded\"}],\"context\":\"compose\\nreply\",\"locale\":\"fr\"}",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_invalid",route:"POST /assist/complete",kind:"invalid-input",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[]}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_disabled",route:"POST /assist/complete",kind:"disabled",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"},{\"role\":\"system\",\"content\":\"downgraded\"}],\"context\":\"compose\\nreply\",\"locale\":\"fr\"}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(false),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_bad_json",route:"POST /assist/complete",kind:"bad-json",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_trailing",route:"POST /assist/complete",kind:"trailing-json",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"user\",\"content\":\"x\"}]} {}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_role",route:"POST /assist/complete",kind:"invalid-role",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"tool\",\"content\":\"x\"}]}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_case_fold",route:"POST /assist/complete",kind:"case-folded-keys",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"MESSAGES\":[{\"ROLE\":\"user\",\"Content\":\"folded\"}],\"Context\":null}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_unconfigured",route:"POST /assist/complete",kind:"unconfigured",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"},{\"role\":\"system\",\"content\":\"downgraded\"}],\"context\":\"compose\\nreply\",\"locale\":\"fr\"}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_bad_url",route:"POST /assist/complete",kind:"bad-provider-url",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"},{\"role\":\"system\",\"content\":\"downgraded\"}],\"context\":\"compose\\nreply\",\"locale\":\"fr\"}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::BadUrl,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_upstream_error",route:"POST /assist/complete",kind:"provider-error",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"},{\"role\":\"system\",\"content\":\"downgraded\"}],\"context\":\"compose\\nreply\",\"locale\":\"fr\"}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Fail,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_no_choices",route:"POST /assist/complete",kind:"provider-no-choices",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"},{\"role\":\"system\",\"content\":\"downgraded\"}],\"context\":\"compose\\nreply\",\"locale\":\"fr\"}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Empty,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_sealed_key",route:"POST /assist/complete",kind:"sealed-api-key",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"},{\"role\":\"system\",\"content\":\"downgraded\"}],\"context\":\"compose\\nreply\",\"locale\":\"fr\"}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Sealed,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"assist_anonymous",route:"POST /assist/complete",kind:"unauthenticated",method:"POST",uri:"/api/assist/complete",headers:vec![("content-type","application/json")],body:"{\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"},{\"role\":\"system\",\"content\":\"downgraded\"}],\"context\":\"compose\\nreply\",\"locale\":\"fr\"}",auth:Auth::None,cfg:Cfg::Default,forwarded:true,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"stream_success",route:"POST /assist/stream",kind:"success",method:"POST",uri:"/api/assist/stream",headers:vec![("content-type","application/json")],body:"{}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"stream_foreign",route:"POST /assist/stream",kind:"cross-tenant",method:"POST",uri:"/api/assist/stream",headers:vec![("content-type","application/json")],body:"{}",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"stream_invalid",route:"POST /assist/stream",kind:"invalid-input",method:"POST",uri:"/api/assist/stream",headers:vec![("content-type","application/json")],body:"{",auth:Auth::None,cfg:Cfg::Default,forwarded:true,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"stream_locale",route:"POST /assist/stream",kind:"accept-language",method:"POST",uri:"/api/assist/stream",headers:vec![("content-type","application/json"),("accept-language","fr-CA,en;q=0.5")],body:"{}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_success",route:"POST /chat/messages/{id}/translate",kind:"success",method:"POST",uri:"/api/chat/messages/{message}/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:true,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_repeat",route:"POST /chat/messages/{id}/translate",kind:"repeat",method:"POST",uri:"/api/chat/messages/{message}/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:true,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:true,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_foreign",route:"POST /chat/messages/{id}/translate",kind:"cross-tenant",method:"POST",uri:"/api/chat/messages/{message}/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:true,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_invalid",route:"POST /chat/messages/{id}/translate",kind:"invalid-input",method:"POST",uri:"/api/chat/messages/{message}/translate",headers:vec![("content-type","application/json")],body:"{",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:true,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_no_locale",route:"POST /chat/messages/{id}/translate",kind:"missing-locale",method:"POST",uri:"/api/chat/messages/{message}/translate",headers:vec![("content-type","application/json")],body:"{}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:true,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_assist_off",route:"POST /chat/messages/{id}/translate",kind:"assist-disabled",method:"POST",uri:"/api/chat/messages/{message}/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(false),provider:Provider::Ok,compliance:false,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_unconfigured",route:"POST /chat/messages/{id}/translate",kind:"unconfigured",method:"POST",uri:"/api/chat/messages/{message}/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::None,compliance:false,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_provider_error",route:"POST /chat/messages/{id}/translate",kind:"provider-error",method:"POST",uri:"/api/chat/messages/{message}/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Fail,compliance:true,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_no_audit",route:"POST /chat/messages/{id}/translate",kind:"compliance-off",method:"POST",uri:"/api/chat/messages/{message}/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_unknown_message",route:"POST /chat/messages/{id}/translate",kind:"unknown-message",method:"POST",uri:"/api/chat/messages/999999999/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:true,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_bad_id",route:"POST /chat/messages/{id}/translate",kind:"bad-id",method:"POST",uri:"/api/chat/messages/abc/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:true,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_chat_off",route:"POST /chat/messages/{id}/translate",kind:"chat-disabled",method:"POST",uri:"/api/chat/messages/1/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Ok,compliance:false,chat:false,toggles:vec![],health:None,telemetry:None}},
        Case{name:"translate_sealed_key",route:"POST /chat/messages/{id}/translate",kind:"sealed-api-key",method:"POST",uri:"/api/chat/messages/{message}/translate",headers:vec![("content-type","application/json")],body:"{\"targetLocale\":\"fr\",\"userId\":0}",auth:Auth::Actor,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:Some(true),provider:Provider::Sealed,compliance:false,chat:true,toggles:vec![],health:None,telemetry:None}},
        Case{name:"telemetry_proof_success",route:"POST /telemetry device-proof",kind:"success",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":{device},\"app_version\":\"1.0\",\"os_version\":\"test\",\"crash_count\":2,\"uptime_hours\":3,\"feature_usage\":{\"search\":4}}",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",true)],health:None,telemetry:Some("valid")}},
        Case{name:"telemetry_proof_legacy_bad_mac",route:"POST /telemetry device-proof",kind:"legacy-invalid-hmac",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":{device}}",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",true)],health:None,telemetry:Some("legacy-bad-mac")}},
        Case{name:"telemetry_proof_foreign",route:"POST /telemetry device-proof",kind:"cross-tenant",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":{foreign_device}}",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",true)],health:None,telemetry:Some("foreign")}},
        Case{name:"telemetry_proof_invalid",route:"POST /telemetry device-proof",kind:"invalid-input",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":{device},\"crash_count\":\"bad\"}",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",true)],health:None,telemetry:Some("valid")}},
        Case{name:"telemetry_proof_repeat",route:"POST /telemetry device-proof",kind:"repeat",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":{device}}",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:true,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",true)],health:None,telemetry:Some("valid")}},
        Case{name:"telemetry_off_success",route:"POST /telemetry toggle-off",kind:"success",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":1}",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",false)],health:None,telemetry:None}},
        Case{name:"telemetry_off_foreign",route:"POST /telemetry toggle-off",kind:"cross-tenant",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":{foreign_user}}",auth:Auth::Foreign,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",false)],health:None,telemetry:None}},
        Case{name:"telemetry_off_invalid",route:"POST /telemetry toggle-off",kind:"invalid-input",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",false)],health:None,telemetry:None}},
        Case{name:"telemetry_proof_legacy_valid",route:"POST /telemetry device-proof",kind:"legacy-valid-hmac",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":{device}}",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",true)],health:None,telemetry:Some("legacy-valid")}},
        Case{name:"telemetry_proof_body_mismatch",route:"POST /telemetry device-proof",kind:"body-digest-mismatch",method:"POST",uri:"/api/telemetry",headers:vec![("content-type","application/json")],body:"{\"device_id\":{device}}",auth:Auth::None,cfg:Cfg::Default,forwarded:false,repeat:false,contract:false,world:World{assist:None,provider:Provider::None,compliance:false,chat:false,toggles:vec![("device_telemetry",true)],health:None,telemetry:Some("body-mismatch")}},
    ]
}

#[tokio::test]
async fn yaml_success() -> Result<(), BoxError> {
    run("yaml_success").await
}

#[tokio::test]
async fn yaml_foreign() -> Result<(), BoxError> {
    run("yaml_foreign").await
}

#[tokio::test]
async fn yaml_invalid() -> Result<(), BoxError> {
    run("yaml_invalid").await
}

#[tokio::test]
async fn yaml_head() -> Result<(), BoxError> {
    run("yaml_head").await
}

#[tokio::test]
async fn json_success() -> Result<(), BoxError> {
    run("json_success").await
}

#[tokio::test]
async fn json_foreign() -> Result<(), BoxError> {
    run("json_foreign").await
}

#[tokio::test]
async fn json_invalid() -> Result<(), BoxError> {
    run("json_invalid").await
}

#[tokio::test]
async fn json_head() -> Result<(), BoxError> {
    run("json_head").await
}

#[tokio::test]
async fn docs_success() -> Result<(), BoxError> {
    run("docs_success").await
}

#[tokio::test]
async fn docs_foreign() -> Result<(), BoxError> {
    run("docs_foreign").await
}

#[tokio::test]
async fn docs_invalid() -> Result<(), BoxError> {
    run("docs_invalid").await
}

#[tokio::test]
async fn docs_head() -> Result<(), BoxError> {
    run("docs_head").await
}

#[tokio::test]
async fn redoc_success() -> Result<(), BoxError> {
    run("redoc_success").await
}

#[tokio::test]
async fn redoc_foreign() -> Result<(), BoxError> {
    run("redoc_foreign").await
}

#[tokio::test]
async fn redoc_invalid() -> Result<(), BoxError> {
    run("redoc_invalid").await
}

#[tokio::test]
async fn redoc_head() -> Result<(), BoxError> {
    run("redoc_head").await
}

#[tokio::test]
async fn logo_success() -> Result<(), BoxError> {
    run("logo_success").await
}

#[tokio::test]
async fn logo_foreign() -> Result<(), BoxError> {
    run("logo_foreign").await
}

#[tokio::test]
async fn logo_invalid() -> Result<(), BoxError> {
    run("logo_invalid").await
}

#[tokio::test]
async fn logo_head() -> Result<(), BoxError> {
    run("logo_head").await
}

#[tokio::test]
async fn font400_success() -> Result<(), BoxError> {
    run("font400_success").await
}

#[tokio::test]
async fn font400_foreign() -> Result<(), BoxError> {
    run("font400_foreign").await
}

#[tokio::test]
async fn font400_invalid() -> Result<(), BoxError> {
    run("font400_invalid").await
}

#[tokio::test]
async fn font400_head() -> Result<(), BoxError> {
    run("font400_head").await
}

#[tokio::test]
async fn font500_success() -> Result<(), BoxError> {
    run("font500_success").await
}

#[tokio::test]
async fn font500_foreign() -> Result<(), BoxError> {
    run("font500_foreign").await
}

#[tokio::test]
async fn font500_invalid() -> Result<(), BoxError> {
    run("font500_invalid").await
}

#[tokio::test]
async fn font500_head() -> Result<(), BoxError> {
    run("font500_head").await
}

#[tokio::test]
async fn cert_hint_success() -> Result<(), BoxError> {
    run("cert_hint_success").await
}

#[tokio::test]
async fn cert_hint_foreign() -> Result<(), BoxError> {
    run("cert_hint_foreign").await
}

#[tokio::test]
async fn cert_hint_invalid() -> Result<(), BoxError> {
    run("cert_hint_invalid").await
}

#[tokio::test]
async fn cert_hint_head() -> Result<(), BoxError> {
    run("cert_hint_head").await
}

#[tokio::test]
async fn ready_success() -> Result<(), BoxError> {
    run("ready_success").await
}

#[tokio::test]
async fn ready_foreign() -> Result<(), BoxError> {
    run("ready_foreign").await
}

#[tokio::test]
async fn ready_invalid() -> Result<(), BoxError> {
    run("ready_invalid").await
}

#[tokio::test]
async fn ready_head() -> Result<(), BoxError> {
    run("ready_head").await
}

#[tokio::test]
async fn full_yaml_success() -> Result<(), BoxError> {
    run("full_yaml_success").await
}

#[tokio::test]
async fn full_yaml_foreign() -> Result<(), BoxError> {
    run("full_yaml_foreign").await
}

#[tokio::test]
async fn full_yaml_invalid() -> Result<(), BoxError> {
    run("full_yaml_invalid").await
}

#[tokio::test]
async fn full_yaml_admin_without_role() -> Result<(), BoxError> {
    run("full_yaml_admin_without_role").await
}

#[tokio::test]
async fn full_json_success() -> Result<(), BoxError> {
    run("full_json_success").await
}

#[tokio::test]
async fn full_json_foreign() -> Result<(), BoxError> {
    run("full_json_foreign").await
}

#[tokio::test]
async fn full_json_invalid() -> Result<(), BoxError> {
    run("full_json_invalid").await
}

#[tokio::test]
async fn full_json_admin_without_role() -> Result<(), BoxError> {
    run("full_json_admin_without_role").await
}

#[tokio::test]
async fn downloads_success() -> Result<(), BoxError> {
    run("downloads_success").await
}

#[tokio::test]
async fn downloads_foreign() -> Result<(), BoxError> {
    run("downloads_foreign").await
}

#[tokio::test]
async fn downloads_invalid() -> Result<(), BoxError> {
    run("downloads_invalid").await
}

#[tokio::test]
async fn downloads_head() -> Result<(), BoxError> {
    run("downloads_head").await
}

#[tokio::test]
async fn platform_success() -> Result<(), BoxError> {
    run("platform_success").await
}

#[tokio::test]
async fn platform_foreign() -> Result<(), BoxError> {
    run("platform_foreign").await
}

#[tokio::test]
async fn platform_invalid() -> Result<(), BoxError> {
    run("platform_invalid").await
}

#[tokio::test]
async fn platform_head() -> Result<(), BoxError> {
    run("platform_head").await
}

#[tokio::test]
async fn asset_success() -> Result<(), BoxError> {
    run("asset_success").await
}

#[tokio::test]
async fn asset_foreign() -> Result<(), BoxError> {
    run("asset_foreign").await
}

#[tokio::test]
async fn asset_invalid() -> Result<(), BoxError> {
    run("asset_invalid").await
}

#[tokio::test]
async fn asset_dot() -> Result<(), BoxError> {
    run("asset_dot").await
}

#[tokio::test]
async fn asset_unicode() -> Result<(), BoxError> {
    run("asset_unicode").await
}

#[tokio::test]
async fn asset_head() -> Result<(), BoxError> {
    run("asset_head").await
}

#[tokio::test]
async fn favicon_success() -> Result<(), BoxError> {
    run("favicon_success").await
}

#[tokio::test]
async fn favicon_foreign() -> Result<(), BoxError> {
    run("favicon_foreign").await
}

#[tokio::test]
async fn favicon_invalid() -> Result<(), BoxError> {
    run("favicon_invalid").await
}

#[tokio::test]
async fn favicon_unconfigured() -> Result<(), BoxError> {
    run("favicon_unconfigured").await
}

#[tokio::test]
async fn health_success() -> Result<(), BoxError> {
    run("health_success").await
}

#[tokio::test]
async fn health_foreign() -> Result<(), BoxError> {
    run("health_foreign").await
}

#[tokio::test]
async fn health_invalid() -> Result<(), BoxError> {
    run("health_invalid").await
}

#[tokio::test]
async fn health_head() -> Result<(), BoxError> {
    run("health_head").await
}

#[tokio::test]
async fn health_warn() -> Result<(), BoxError> {
    run("health_warn").await
}

#[tokio::test]
async fn health_error() -> Result<(), BoxError> {
    run("health_error").await
}

#[tokio::test]
async fn metrics_success() -> Result<(), BoxError> {
    run("metrics_success").await
}

#[tokio::test]
async fn metrics_foreign() -> Result<(), BoxError> {
    run("metrics_foreign").await
}

#[tokio::test]
async fn metrics_invalid() -> Result<(), BoxError> {
    run("metrics_invalid").await
}

#[tokio::test]
async fn metrics_unset() -> Result<(), BoxError> {
    run("metrics_unset").await
}

#[tokio::test]
async fn metrics_open() -> Result<(), BoxError> {
    run("metrics_open").await
}

#[tokio::test]
async fn setjoin_success() -> Result<(), BoxError> {
    run("setjoin_success").await
}

#[tokio::test]
async fn setjoin_foreign() -> Result<(), BoxError> {
    run("setjoin_foreign").await
}

#[tokio::test]
async fn setjoin_invalid() -> Result<(), BoxError> {
    run("setjoin_invalid").await
}

#[tokio::test]
async fn setjoin_configured() -> Result<(), BoxError> {
    run("setjoin_configured").await
}

#[tokio::test]
async fn setjoin_head() -> Result<(), BoxError> {
    run("setjoin_head").await
}

#[tokio::test]
async fn autoconfig_success() -> Result<(), BoxError> {
    run("autoconfig_success").await
}

#[tokio::test]
async fn autoconfig_foreign() -> Result<(), BoxError> {
    run("autoconfig_foreign").await
}

#[tokio::test]
async fn autoconfig_invalid() -> Result<(), BoxError> {
    run("autoconfig_invalid").await
}

#[tokio::test]
async fn autoconfig_imap_plain() -> Result<(), BoxError> {
    run("autoconfig_imap_plain").await
}

#[tokio::test]
async fn autoconfig_head() -> Result<(), BoxError> {
    run("autoconfig_head").await
}

#[tokio::test]
async fn caldav_success() -> Result<(), BoxError> {
    run("caldav_success").await
}

#[tokio::test]
async fn caldav_foreign() -> Result<(), BoxError> {
    run("caldav_foreign").await
}

#[tokio::test]
async fn caldav_invalid() -> Result<(), BoxError> {
    run("caldav_invalid").await
}

#[tokio::test]
async fn caldav_disabled() -> Result<(), BoxError> {
    run("caldav_disabled").await
}

#[tokio::test]
async fn caldav_head() -> Result<(), BoxError> {
    run("caldav_head").await
}

#[tokio::test]
async fn carddav_success() -> Result<(), BoxError> {
    run("carddav_success").await
}

#[tokio::test]
async fn carddav_foreign() -> Result<(), BoxError> {
    run("carddav_foreign").await
}

#[tokio::test]
async fn carddav_invalid() -> Result<(), BoxError> {
    run("carddav_invalid").await
}

#[tokio::test]
async fn carddav_disabled() -> Result<(), BoxError> {
    run("carddav_disabled").await
}

#[tokio::test]
async fn carddav_head() -> Result<(), BoxError> {
    run("carddav_head").await
}

#[tokio::test]
async fn discover_success() -> Result<(), BoxError> {
    run("discover_success").await
}

#[tokio::test]
async fn discover_foreign() -> Result<(), BoxError> {
    run("discover_foreign").await
}

#[tokio::test]
async fn discover_invalid() -> Result<(), BoxError> {
    run("discover_invalid").await
}

#[tokio::test]
async fn discover_empty() -> Result<(), BoxError> {
    run("discover_empty").await
}

#[tokio::test]
async fn telemetry_success() -> Result<(), BoxError> {
    run("telemetry_success").await
}

#[tokio::test]
async fn telemetry_foreign() -> Result<(), BoxError> {
    run("telemetry_foreign").await
}

#[tokio::test]
async fn telemetry_invalid() -> Result<(), BoxError> {
    run("telemetry_invalid").await
}

#[tokio::test]
async fn telemetry_enabled_unproven() -> Result<(), BoxError> {
    run("telemetry_enabled_unproven").await
}

#[tokio::test]
async fn telemetry_enabled_invalid() -> Result<(), BoxError> {
    run("telemetry_enabled_invalid").await
}

#[tokio::test]
async fn assist_success() -> Result<(), BoxError> {
    run("assist_success").await
}

#[tokio::test]
async fn assist_foreign() -> Result<(), BoxError> {
    run("assist_foreign").await
}

#[tokio::test]
async fn assist_invalid() -> Result<(), BoxError> {
    run("assist_invalid").await
}

#[tokio::test]
async fn assist_disabled() -> Result<(), BoxError> {
    run("assist_disabled").await
}

#[tokio::test]
async fn assist_bad_json() -> Result<(), BoxError> {
    run("assist_bad_json").await
}

#[tokio::test]
async fn assist_trailing() -> Result<(), BoxError> {
    run("assist_trailing").await
}

#[tokio::test]
async fn assist_role() -> Result<(), BoxError> {
    run("assist_role").await
}

#[tokio::test]
async fn assist_case_fold() -> Result<(), BoxError> {
    run("assist_case_fold").await
}

#[tokio::test]
async fn assist_unconfigured() -> Result<(), BoxError> {
    run("assist_unconfigured").await
}

#[tokio::test]
async fn assist_bad_url() -> Result<(), BoxError> {
    run("assist_bad_url").await
}

#[tokio::test]
async fn assist_upstream_error() -> Result<(), BoxError> {
    run("assist_upstream_error").await
}

#[tokio::test]
async fn assist_no_choices() -> Result<(), BoxError> {
    run("assist_no_choices").await
}

#[tokio::test]
async fn assist_sealed_key() -> Result<(), BoxError> {
    run("assist_sealed_key").await
}

#[tokio::test]
async fn assist_anonymous() -> Result<(), BoxError> {
    run("assist_anonymous").await
}

#[tokio::test]
async fn stream_success() -> Result<(), BoxError> {
    run("stream_success").await
}

#[tokio::test]
async fn stream_foreign() -> Result<(), BoxError> {
    run("stream_foreign").await
}

#[tokio::test]
async fn stream_invalid() -> Result<(), BoxError> {
    run("stream_invalid").await
}

#[tokio::test]
async fn stream_locale() -> Result<(), BoxError> {
    run("stream_locale").await
}

#[tokio::test]
async fn translate_success() -> Result<(), BoxError> {
    run("translate_success").await
}

#[tokio::test]
async fn translate_repeat() -> Result<(), BoxError> {
    run("translate_repeat").await
}

#[tokio::test]
async fn translate_foreign() -> Result<(), BoxError> {
    run("translate_foreign").await
}

#[tokio::test]
async fn translate_invalid() -> Result<(), BoxError> {
    run("translate_invalid").await
}

#[tokio::test]
async fn translate_no_locale() -> Result<(), BoxError> {
    run("translate_no_locale").await
}

#[tokio::test]
async fn translate_assist_off() -> Result<(), BoxError> {
    run("translate_assist_off").await
}

#[tokio::test]
async fn translate_unconfigured() -> Result<(), BoxError> {
    run("translate_unconfigured").await
}

#[tokio::test]
async fn translate_provider_error() -> Result<(), BoxError> {
    run("translate_provider_error").await
}

#[tokio::test]
async fn translate_no_audit() -> Result<(), BoxError> {
    run("translate_no_audit").await
}

#[tokio::test]
async fn translate_unknown_message() -> Result<(), BoxError> {
    run("translate_unknown_message").await
}

#[tokio::test]
async fn translate_bad_id() -> Result<(), BoxError> {
    run("translate_bad_id").await
}

#[tokio::test]
async fn translate_chat_off() -> Result<(), BoxError> {
    run("translate_chat_off").await
}

#[tokio::test]
async fn translate_sealed_key() -> Result<(), BoxError> {
    run("translate_sealed_key").await
}

#[tokio::test]
async fn telemetry_proof_success() -> Result<(), BoxError> {
    run("telemetry_proof_success").await
}

#[tokio::test]
async fn telemetry_proof_legacy_bad_mac() -> Result<(), BoxError> {
    run("telemetry_proof_legacy_bad_mac").await
}

#[tokio::test]
async fn telemetry_proof_foreign() -> Result<(), BoxError> {
    run("telemetry_proof_foreign").await
}

#[tokio::test]
async fn telemetry_proof_invalid() -> Result<(), BoxError> {
    run("telemetry_proof_invalid").await
}

#[tokio::test]
async fn telemetry_proof_repeat() -> Result<(), BoxError> {
    run("telemetry_proof_repeat").await
}

#[tokio::test]
async fn telemetry_off_success() -> Result<(), BoxError> {
    run("telemetry_off_success").await
}

#[tokio::test]
async fn telemetry_off_foreign() -> Result<(), BoxError> {
    run("telemetry_off_foreign").await
}

#[tokio::test]
async fn telemetry_off_invalid() -> Result<(), BoxError> {
    run("telemetry_off_invalid").await
}

#[tokio::test]
async fn telemetry_proof_legacy_valid() -> Result<(), BoxError> {
    run("telemetry_proof_legacy_valid").await
}

#[tokio::test]
async fn telemetry_proof_body_mismatch() -> Result<(), BoxError> {
    run("telemetry_proof_body_mismatch").await
}

#[tokio::test]
async fn yaml_rejects_status() -> Result<(), BoxError> {
    run_inner("yaml_success", Mutant::Status).await
}

#[tokio::test]
async fn json_rejects_status() -> Result<(), BoxError> {
    run_inner("json_success", Mutant::Status).await
}

#[tokio::test]
async fn docs_rejects_status() -> Result<(), BoxError> {
    run_inner("docs_success", Mutant::Status).await
}

#[tokio::test]
async fn redoc_rejects_status() -> Result<(), BoxError> {
    run_inner("redoc_success", Mutant::Status).await
}

#[tokio::test]
async fn logo_rejects_status() -> Result<(), BoxError> {
    run_inner("logo_success", Mutant::Status).await
}

#[tokio::test]
async fn font400_rejects_status() -> Result<(), BoxError> {
    run_inner("font400_success", Mutant::Status).await
}

#[tokio::test]
async fn font500_rejects_status() -> Result<(), BoxError> {
    run_inner("font500_success", Mutant::Status).await
}

#[tokio::test]
async fn cert_hint_rejects_status() -> Result<(), BoxError> {
    run_inner("cert_hint_success", Mutant::Status).await
}

#[tokio::test]
async fn ready_rejects_status() -> Result<(), BoxError> {
    run_inner("ready_success", Mutant::Status).await
}

#[tokio::test]
async fn full_yaml_rejects_status() -> Result<(), BoxError> {
    run_inner("full_yaml_success", Mutant::Status).await
}

#[tokio::test]
async fn full_json_rejects_status() -> Result<(), BoxError> {
    run_inner("full_json_success", Mutant::Status).await
}

#[tokio::test]
async fn downloads_rejects_status() -> Result<(), BoxError> {
    run_inner("downloads_success", Mutant::Status).await
}

#[tokio::test]
async fn platform_rejects_status() -> Result<(), BoxError> {
    run_inner("platform_success", Mutant::Status).await
}

#[tokio::test]
async fn asset_rejects_status() -> Result<(), BoxError> {
    run_inner("asset_success", Mutant::Status).await
}

#[tokio::test]
async fn favicon_rejects_status() -> Result<(), BoxError> {
    run_inner("favicon_success", Mutant::Status).await
}

#[tokio::test]
async fn health_rejects_status() -> Result<(), BoxError> {
    run_inner("health_success", Mutant::Status).await
}

#[tokio::test]
async fn metrics_rejects_status() -> Result<(), BoxError> {
    run_inner("metrics_success", Mutant::Status).await
}

#[tokio::test]
async fn setjoin_rejects_status() -> Result<(), BoxError> {
    run_inner("setjoin_success", Mutant::Status).await
}

#[tokio::test]
async fn autoconfig_rejects_status() -> Result<(), BoxError> {
    run_inner("autoconfig_success", Mutant::Status).await
}

#[tokio::test]
async fn caldav_rejects_status() -> Result<(), BoxError> {
    run_inner("caldav_success", Mutant::Status).await
}

#[tokio::test]
async fn carddav_rejects_status() -> Result<(), BoxError> {
    run_inner("carddav_success", Mutant::Status).await
}

#[tokio::test]
async fn discover_rejects_status() -> Result<(), BoxError> {
    run_inner("discover_success", Mutant::Status).await
}

#[tokio::test]
async fn telemetry_rejects_status() -> Result<(), BoxError> {
    run_inner("telemetry_success", Mutant::Status).await
}

#[tokio::test]
async fn assist_rejects_status() -> Result<(), BoxError> {
    run_inner("assist_success", Mutant::Status).await
}

#[tokio::test]
async fn stream_rejects_status() -> Result<(), BoxError> {
    run_inner("stream_success", Mutant::Status).await
}

#[tokio::test]
async fn translate_rejects_status() -> Result<(), BoxError> {
    run_inner("translate_success", Mutant::Status).await
}

#[tokio::test]
async fn telemetry_proof_rejects_status() -> Result<(), BoxError> {
    run_inner("telemetry_proof_success", Mutant::Status).await
}

#[tokio::test]
async fn telemetry_off_rejects_status() -> Result<(), BoxError> {
    run_inner("telemetry_off_success", Mutant::Status).await
}

#[tokio::test]
async fn autoconfig_oracle_rejects_missing_domain_filter() -> Result<(), BoxError> {
    run_inner("autoconfig_foreign", Mutant::NoFilter).await
}

#[tokio::test]
async fn assist_oracle_rejects_missing_authentication() -> Result<(), BoxError> {
    run_inner("assist_anonymous", Mutant::NoFilter).await
}
