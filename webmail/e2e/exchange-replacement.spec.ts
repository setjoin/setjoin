import { expect, test, type Locator, type Page, type Route } from '@playwright/test';

const permissions = ['read','run','decide','attest','audit','publish','delete'].map((name) => `exchange.assessment.${name}`);
const registry = {
  schemaVersion:'setjoin.exchange.projection/v1',registryVersion:1,catalogVersion:1,sourceDigest:'c'.repeat(64),
  capabilities:Array.from({length:31},(_,index)=>({id:`EX-CAP-${String(index).padStart(2,'0')}`,category:'mailbox',outcome:{zh:`功能 ${index}`,en:`Outcome ${index}`},mappingMaximum:'native',claimMaximum:'experimental',phaseImpacts:[]})),
  supportCells:[{id:'EX2019-ONPREM-INITIAL',productFamily:'Exchange Server 2019',topology:'on_premises',admission:'unassessed',digest:'a'.repeat(64),collectorVersion:'1'}],
};
const project={id:9,domainId:1,name:'Exchange 华东',state:'active',retentionUntil:null,createdAt:'2026-08-23T00:00:00Z',updatedAt:'2026-08-23T00:00:00Z'};
const run={id:17,projectId:9,generation:2,state:'preflight',supportCellId:'EX2019-ONPREM-INITIAL',supportCellDigest:'a'.repeat(64),registryVersion:1,registryDigest:'c'.repeat(64),catalogVersion:1,collectorVersion:'1',errorCode:null,createdAt:'2026-08-23T00:00:00Z',updatedAt:'2026-08-23T00:00:00Z',completedAt:null};

async function json(route:Route, body:unknown,status=200){await route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});}
async function clickMutation(page:Page, button:Locator, path:string){
  await expect(button).toBeEnabled();
  await Promise.all([
    page.waitForResponse((response)=>response.url().includes(path)&&response.request().method()!=='GET'),
    button.click(),
  ]);
  await expect(button).toBeEnabled();
}
async function install(page:Page, granted=permissions, mutations:string[]=[]){
  await page.addInitScript(()=>localStorage.setItem('sj-welcome-tour:admin@test.local','1'));
  await page.route(/^https?:\/\/[^/]+\/(auth|jmap|api)\b/,(route)=>json(route,{}));
  await page.route(/\/auth\/me(?:\?|$)/,(route)=>json(route,{email:'admin@test.local',display_name:'Admin',is_admin:true,has_mailbox:true,totp_enabled:true,delegates:[],impersonating:false}));
  await page.route(/(?:\.well-known\/jmap|\/jmap\/session)(?:\?|$)/,(route)=>json(route,{apiUrl:'/jmap',downloadUrl:'/blobs/{blobId}',uploadUrl:'/upload',eventSourceUrl:'/events',state:'1',username:'admin@test.local',accounts:{admin:{name:'admin',isPersonal:true,accountCapabilities:{}}},primaryAccounts:{'urn:ietf:params:jmap:mail':'admin'},capabilities:{'urn:setjoin:params:jmap:mail':{admin:{consoles:['mail'],permissions:granted}}}}));
  await page.route(/\/api\/user\/offline\/caps(?:\?|$)/,(route)=>json(route,{allowed:false}));
  await page.route(/\/api\/admin\/exchange-replacement\//,(route)=>{if(route.request().method()!=='GET') mutations.push(route.request().url()); return json(route,{...run,generation:run.generation+1},route.request().method()==='POST'?201:200);});
  await page.route(/\/api\/admin\/exchange-replacement\/registry$/,(route)=>json(route,registry));
  await page.route(/\/api\/admin\/exchange-replacement\/projects$/,(route)=>json(route,route.request().method()==='GET'?[project]:project,route.request().method()==='GET'?200:201));
  await page.route(/\/api\/admin\/exchange-replacement\/projects\/9\/runs$/,(route)=>json(route,route.request().method()==='GET'?[run]:run,route.request().method()==='GET'?200:201));
  await page.route(/\/api\/admin\/exchange-replacement\/runs\/17\/audit$/,(route)=>json(route,{claims:[{projection_digest:'d'.repeat(64)}],attestations:[],evidence:[],publications:[]}));
}

test.describe('Exchange replacement evidence-gated admin journey @admin',()=>{
  test.use({storageState:{cookies:[],origins:[]},serviceWorkers:'block',timezoneId:'UTC'});
  test('all six views, 31 outcomes, and every authorized mutation stay visible and bounded',async({page})=>{
    const mutations:string[]=[]; await install(page,permissions,mutations); await page.goto('/admin/exchange-replacement');
    await expect(page.getByText(/仅用于评估/)).toBeVisible();
    for(const name of ['概览','评估运行','功能结果','映射','文档','设置']) await expect(page.getByRole('button',{name,exact:true})).toBeVisible();
    await page.getByRole('button',{name:'功能结果'}).click(); await expect(page.locator('.outcomes article')).toHaveCount(31); await expect(page.getByText('EX-CAP-00')).toBeVisible();
    await page.getByRole('button',{name:'评估运行'}).click();
    await page.getByLabel('域 ID').fill('1'); await page.getByLabel('新项目名称').fill('迁移评估');
    const createProject = page.getByRole('button',{name:'创建项目'}); await clickMutation(page,createProject,'/projects');
    const createRun = page.getByRole('button',{name:'新建运行'}); await clickMutation(page,createRun,'/projects/9/runs');
    const transition = page.getByRole('button',{name:'更新运行状态'}); await clickMutation(page,transition,'/runs/17/transition');
    await page.getByLabel('SHA-256').fill('b'.repeat(64)); const attest = page.getByRole('button',{name:'记录证明'}); await clickMutation(page,attest,'/runs/17/attestations');
    await page.getByRole('button',{name:'映射',exact:true}).click(); await page.getByLabel('功能').selectOption('EX-CAP-00'); await page.getByLabel('原因').fill('逐项验证');
    const decide = page.getByRole('button',{name:'记录决定'}); await clickMutation(page,decide,'/runs/17/decisions');
    await page.getByRole('button',{name:'文档'}).click(); const resolve = page.getByRole('button',{name:'解析声明快照'}); await clickMutation(page,resolve,'/runs/17/claims/resolve');
    await page.getByLabel('投影摘要').fill('d'.repeat(64)); const publish = page.getByRole('button',{name:'发布',exact:true}); await clickMutation(page,publish,'/runs/17/publications');
    await page.getByRole('button',{name:'设置'}).click(); await page.getByLabel('原因').fill('保留期结束'); const deletion = page.getByRole('button',{name:'提交删除请求'});
    await clickMutation(page,deletion,'/projects/9/deletions');
    expect(mutations.some((url)=>url.includes('/projects/9/deletions'))).toBe(true);
    await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
  });

  test('read-only administrator sees evidence but no mutating controls on Chinese mobile',async({page})=>{
    await page.setViewportSize({width:375,height:812}); await install(page,['exchange.assessment.read']); await page.goto('/admin/exchange-replacement');
    await expect(page.getByText('评估状态')).toBeVisible(); await page.getByRole('button',{name:'评估运行'}).click();
    for(const name of ['新建运行','创建项目','记录证明']) await expect(page.getByRole('button',{name})).toHaveCount(0);
    await page.getByRole('button',{name:'设置'}).click(); await expect(page.getByText('已授予')).toHaveCount(1); await expect(page.getByText('未授予')).toHaveCount(6);
  });
});
