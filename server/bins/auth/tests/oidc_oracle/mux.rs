use super::grants::Env;
use super::*;
pub(super) async fn run(route: &str, kind: &str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let env = Env::start(false).await?;
    let result=async{
  let(path,key)=match route{"well_known_mux"=>("/.well-known/not-a-provider-route","* /.well-known/ mux"),"authorize_mux"=>("/authorize/unknown","* /authorize/"),"oauth_namespace"=>("/oauth","* /oauth"),"gateway_oauth_mux"=>("/oauth/unknown","* /oauth/"),_=>("/oauth/unknown","* /oauth/ mux")};
  let before=env.stores(&[]).await?;env.status_mutation.store(mutant,std::sync::atomic::Ordering::SeqCst);
  let public=matches!(route,"authorize_mux"|"oauth_namespace"|"gateway_oauth_mux");
  let front=if public{Some(gateway_mode(env.auth.addr,if env.recording{Some(std::env::var("GOFREE_RECORD_GATEWAY_UPSTREAM").expect("public namespace recording requires the owned Go mail gateway"))}else{None},true,Some(env.status_mutation.clone())).await)}else{None};
  let response=request(front.as_ref().map_or(env.gw.addr,|f|f.addr),"GET",path,if kind=="invalid-input"{"{".into()}else{String::new()},if kind=="cross-tenant"{&[("authorization","Bearer foreign")]}else{&[]}).await;
  if let Some(front)=front{let metrics=request(front.addr,"GET","/_gateway/metrics",String::new(),&[]).await;front.close().await;if !env.recording&&!metrics?.2.contains("setjoin_gateway_proxied_to_go_total 0"){return Err("native namespace used Go".into());}}let response=response?;
  if !mutant&&response.0!=404{return Err(format!("mux status {} body {}",response.0,response.2).into());}
  let after=env.stores(&[]).await?;
  let actual=json!({"format":1,"go_source":SOURCE,"route":key,"case":format!("{route}-{kind}"),"observation":{"request":{"method":"*","path":key.split(' ').nth(1).unwrap(),"wire_method":"GET","wire_path":path},"response":{"status":response.0,"headers":response.1,"body":response.2},"effects":[{"table":"auth_attempts","before":before["attempts"],"after":after["attempts"]}],"audit":[],"notify":[]}});
  let file=corpus().join("goldens").join(format!("{route}-{kind}.json"));if env.recording&&!file.exists(){golden::record(&file,&actual)?;}
  super::grants::observe(env.recording,&file,&actual,&before,&after,mutant)?;Ok::<(),Err>(())
 }.await;
    env.close().await?;
    result
}
