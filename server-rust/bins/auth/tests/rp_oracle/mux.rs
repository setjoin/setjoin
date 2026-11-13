//! The original gateway GET-link alias is a method refusal; unknown namespace
//! shapes retain net/http mux bytes, independently of authentication input.
use super::*;
use setjoin_conformance::golden;
pub async fn run(group: &str, kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await?;
    let result=async{
        let route=if group=="alias"{"GET /auth/oidc/link"}else{"* /auth/oidc/ mux"};
        let method=if group=="mux"&&kind=="invalid-input"{"POST"}else if kind=="head"{"HEAD"}else{"GET"};
        let path=if group=="alias"{"/auth/oidc/link"}else if kind=="invalid-input"{"/auth/oidc/login"}else{"/auth/oidc/missing"};
        let query=if kind=="invalid-input"{"?provider=missing"}else{""};
        let headers=if kind=="cross-tenant"{vec![("authorization","Bearer foreign"),("x-user-id","99999")]}else{vec![]};
        if mutant{env.mutation.store(true,std::sync::atomic::Ordering::SeqCst);}
        let response=request(env.gw.addr,method,&format!("{path}{query}"),"{".into(),&headers).await?;
        let (canonical_method,canonical_path)=if group=="alias"{("GET","/auth/oidc/link")}else{("*","/auth/oidc/")};
        let actual=json!({"format":1,"go_source":SOURCE,"route":route,"case":format!("{group}-{kind}"),"observation":{"request":{"method":canonical_method,"path":canonical_path,"wire_method":method,"wire_path":path,"query":query},"response":{"status":response.0,"headers":response.1,"body":response.2},"effects":[],"audit":[],"notify":[]}});
        let path=corpus().join("goldens").join(format!("{group}-{kind}.json"));
        if env.recording&&!path.exists(){golden::record(&path,&actual)?;}
        let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;
        if mutant{
            let error=golden::compare(&expected,&actual).expect_err("namespace status mutant survived");
            if !error.contains("/observation/response/status"){return Err(error.into());}
            super::observation::compare(&actual,true)?;
            println!("MUTANT-REJECTED: {route} :: status");
        }else{golden::compare(&expected,&actual)?;super::observation::replay(&actual,env.recording)?;println!("GOLDEN-REPLAY: {route} :: {group}-{kind}");}
        Ok::<(),Err>(())
    }.await;
    env.close().await?;
    result
}
