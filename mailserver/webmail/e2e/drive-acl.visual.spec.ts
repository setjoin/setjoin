import { expect,test,type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { apiToken,loginAs,loginAsUser,psql,reloadAfterServiceWorkerControl,setFeature } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

const flags=[
	'feature.drive',
	'feature.drive_node_acl_reads',
	'feature.drive_node_acl_writes',
	'feature.drive_access_governance',
] as const;

async function openAccess(page: Page,spaceName: string,folderName: string,fileName: string,label: string) {
	await page.goto('/drive');
	await page.getByText(spaceName,{ exact:true }).click();
	const fileList=page.locator('.fl__rows');
	await fileList.getByRole('button',{ name:folderName,exact:true }).click();
	const row=fileList.locator('li',{ hasText:fileName });
	await row.hover();
	await row.getByRole('button',{ name:label }).click();
}

async function grant(page: Page,nodeId: number,subjectId: number,preset: 'viewer'|'editor',scope: 'self'|'subtree') {
	const detail=await page.request.get(`/api/drive/nodes/${nodeId}/access`);
	expect(detail.status(),`read ACL epoch for node ${nodeId}`).toBe(200);
	const epoch=String(((await detail.json()) as { epoch:string }).epoch);
	const idempotencyKey=randomUUID();
	const response=await page.request.post(`/api/drive/nodes/${nodeId}/acl`,{
		headers:{ 'Idempotency-Key':idempotencyKey },
		data:{
			subjectKind:'user',subjectId:String(subjectId),preset,scope,
			reason:'E2E Drive ACL visual fixture',expectedEpoch:epoch,idempotencyKey,
		},
	});
	expect(response.status(),`grant ${preset} on node ${nodeId}: ${await response.text()}`).toBe(200);
}

test.describe('Drive ACL visual and interaction matrix @user',()=>{
	test.use({ timezoneId:'UTC',reducedMotion:'reduce',serviceWorkers:'block' });
	let adminToken='';
	let togglesOn=false;

	test.afterEach(async ({ request })=>{
		if (!togglesOn) return;
		for (const key of [...flags].reverse()) await setFeature(request,adminToken,key,false).catch(()=>{});
		togglesOn=false;
	});

	test('manager and request-only states remain usable across locale, theme, and viewport',async ({ page,request })=>{
		adminToken=await apiToken(request,TEST_USERS.admin.email,TEST_USERS.admin.password);
		for (const key of flags) await setFeature(request,adminToken,key,true);
		togglesOn=true;
		await new Promise((resolve)=>setTimeout(resolve,1200));
		await loginAsUser(page);

		const suffix=Date.now();
		const spaceName=`E2E ACL ${suffix}`;
		const fileName='Quarterly roadmap.docx';
		const spaceResponse=await page.request.post('/api/drive/spaces',{
			data:{ name:spaceName,classification:'regular' },
		});
		expect(spaceResponse.status()).toBe(201);
		const spaceId=((await spaceResponse.json()) as { id:number }).id;
		psql(`UPDATE drive_spaces SET acl_mode='acl' WHERE id=${spaceId}`);
		const folderResponse=await page.request.post('/api/drive/nodes',{
			data:{ spaceId,parentId:null,kind:'folder',name:'Strategy' },
		});
		expect(folderResponse.status()).toBe(201);
		const folderId=((await folderResponse.json()) as { id:number }).id;
		const fileResponse=await page.request.post('/api/drive/nodes',{
			data:{ spaceId,parentId:folderId,kind:'file',name:fileName,contentType:'application/vnd.openxmlformats-officedocument.wordprocessingml.document' },
		});
		expect(fileResponse.status()).toBe(201);
		const fileId=((await fileResponse.json()) as { id:number }).id;
		const bobId=Number(psql(`SELECT id FROM users WHERE email='${TEST_USERS.bob.email}'`));
		const adminId=Number(psql(`SELECT id FROM users WHERE email='${TEST_USERS.admin.email}'`));
		await grant(page,folderId,bobId,'viewer','subtree');
		await grant(page,fileId,adminId,'editor','self');

		await page.setViewportSize({ width:1440,height:900 });
		await page.evaluate(()=>{
			localStorage.setItem('locale','en');
			localStorage.setItem('sj-theme','light');
		});
		page = await reloadAfterServiceWorkerControl(page);
		await openAccess(page,spaceName,'Strategy',fileName,'Properties and permissions');
		const drawer=page.getByRole('dialog',{ name:'Properties and permissions' });
		await expect(drawer).toBeVisible();
		await expect(drawer.getByText('Admin Test')).toBeVisible();
		await expect(drawer.getByText('Bob Test')).toBeVisible();
		await expect(drawer.getByText('Inherited (1)')).toBeVisible();
		await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
		await expect(page).toHaveScreenshot('drive-acl-manager-en-light-desktop.png',{ fullPage:true });

		await drawer.getByRole('button',{ name:'Add people' }).click();
		for (const label of ['Viewer','Contributor','Editor','Folder manager']) {
			await expect(drawer.getByRole('radio',{ name:new RegExp(label) })).toBeVisible();
		}
		await expect(drawer.getByRole('radio',{ name:/Custom/ })).toHaveCount(0);
		await expect(page).toHaveScreenshot('drive-acl-grant-en-light-desktop.png',{ fullPage:true });

		const aliceId=Number(psql(`SELECT id FROM users WHERE email='${TEST_USERS.alice.email}'`));
		const bobGrantId=Number(psql(`SELECT id FROM drive_acl_grants WHERE node_id=${folderId} AND subject_user_id=${bobId} AND state='active' ORDER BY id DESC LIMIT 1`));
		psql(`SELECT drive_acl_revoke(${aliceId},${bobGrantId},drive_acl_epoch(${spaceId}),'E2E request-only transition')`);
		psql(`SELECT drive_acl_grant(${aliceId},${fileId},'user',${bobId},'custom',ARRAY['traverse'],'self',NULL,NULL,NULL,'E2E request-only traversal',drive_acl_epoch(${spaceId}),'drive-acl-e2e-traverse-${fileId}')`);

		await loginAs(page,TEST_USERS.bob.email,TEST_USERS.bob.password);
		await page.setViewportSize({ width:375,height:812 });
		await page.evaluate(()=>{
			localStorage.setItem('locale','zh');
			localStorage.setItem('sj-theme','dark');
		});
		page = await reloadAfterServiceWorkerControl(page);
		await openAccess(page,spaceName,'Strategy',fileName,'属性和权限');
		const requestOnly=page.getByRole('dialog',{ name:'属性和权限' });
		await expect(requestOnly).toHaveAttribute('aria-modal','true');
		await expect(requestOnly.getByText('有效访问权限')).toBeVisible();
		await expect(requestOnly.getByRole('button',{ name:'添加人员' })).toHaveCount(0);
		await expect(requestOnly.getByRole('button',{ name:'申请访问权限' })).toBeVisible();
		await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
		await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
		await expect(page).toHaveScreenshot('drive-acl-request-only-zh-dark-mobile.png',{ fullPage:true });
	});
});
