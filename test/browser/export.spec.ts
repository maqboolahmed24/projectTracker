import { expect,test } from '@playwright/test';
import { authenticationFixture } from './authentication-fixture.js';
import { ownerPage } from './planning-helpers.js';

test('CP12: real Worker exports complete plaintext project data only after acknowledgement and final source validation',async({page})=>{
  test.setTimeout(90000);const f=await authenticationFixture();
  try {await ownerPage(page,f);
    const project=await page.evaluate(async()=>{const c=window.clientRuntime,p=await c.projectCreation.create({name:'Private export browser project'});
      const task=await c.planning.createTask({projectId:p.projectId,title:'Private export browser task'});
      await c.collaboration.postComment({projectId:p.projectId,taskId:task.taskId,text:'Private exported discussion'});return p;});
    const uploaded:string[]=[];page.on('request',request=>{if(request.url().includes('/v1/export/'))uploaded.push(request.postData()??'');});
    const file=await page.evaluate(()=>window.clientRuntime.exports.generate({acknowledgePlaintext:true})),document=JSON.parse(file.json);
    expect(file.mimeType).toBe('application/json;charset=utf-8');expect(document.complete).toBe(true);expect(document.projects[0].name).toBe('Private export browser project');
    expect(document.tasks[0].title).toBe('Private export browser task');expect(document.comments[0].text).toBe('Private exported discussion');expect(document.history.planning).toHaveLength(2);
    expect(uploaded.length).toBeGreaterThan(3);expect(uploaded.every(body=>!body.includes('Private export')&&!body.includes('Private exported discussion'))).toBe(true);
    expect(file.json).not.toContain('signingPrivateKey');expect(file.json).not.toContain('ciphertext');expect(file.json).not.toContain('key_envelope');
    let changed=false;await page.route('**/v1/export/finalize',async route=>{changed=true;
      await page.evaluate(async projectId=>{const p=window.clientRuntime.planning;await p.execute({projectId,reviewed:(await p.read(projectId)).pin,command:{action:'edit_project',patch:{}},content:{name:'Changed while exporting'}});},project.projectId);
      await route.continue();},{times:1});
    const denied=await page.evaluate(async()=>{try{await window.clientRuntime.exports.generate({acknowledgePlaintext:true});return false;}catch{return true;}});
    expect(changed).toBe(true);expect(denied).toBe(true);
    const retry=await page.evaluate(()=>window.clientRuntime.exports.generate({acknowledgePlaintext:true}));expect(JSON.parse(retry.json).projects[0].name).toBe('Changed while exporting');
  }finally{await Promise.allSettled([page.evaluate(()=>window.clientRuntime?.close())]);await f.close();}
});
