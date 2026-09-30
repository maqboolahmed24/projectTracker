import {expect,test,type Page} from '@playwright/test';
import {dishonestDocxFixture,pdfFixture,previewFixtures,webpFixture} from '../file-preview-fixtures.js';

async function mount(page:Page,filename:string,bytes:Uint8Array){
 await page.evaluate(({filename,bytes})=>(window as unknown as {previewFile:(filename:string,bytes:number[])=>void}).previewFile(filename,bytes),{filename,bytes:[...bytes]});
}
test('Every supported Office/text preview runs in its disposable browser worker with no document network access',async({page})=>{
 test.setTimeout(90000);const external:string[]=[];page.on('request',request=>{if(new URL(request.url()).origin!=='https://127.0.0.1:3555')external.push(request.url());});
 await page.goto('/preview-test');await page.waitForFunction(()=>typeof(window as unknown as {previewFile:unknown}).previewFile==='function');
 for(const fixture of await previewFixtures()){await mount(page,fixture.filename,fixture.bytes);
  if(['txt','csv'].includes(fixture.filename.split('.').at(-1)!))await expect(page.locator('.file-text-preview')).toContainText(fixture.text);
  else{await expect(page.locator('iframe[title="Preview of '+fixture.filename+'"]')).toBeVisible();await expect(page.frameLocator('iframe').locator('body')).toContainText(fixture.text);await expect(page.frameLocator('iframe').locator('script,iframe,object,img[src],a[href]')).toHaveCount(0);}
 }
 expect(await page.evaluate(()=>(window as unknown as {previewInjected?:boolean}).previewInjected)).toBeUndefined();expect(external).toEqual([]);
});
test('PDF and all supported images render locally without unsafe links or automatic actions',async({page})=>{
 await page.goto('/preview-test');await page.waitForFunction(()=>typeof(window as unknown as {previewFile:unknown}).previewFile==='function');
 await mount(page,'checked.pdf',pdfFixture());await expect(page.locator('.file-pdf-preview canvas')).toBeVisible();await expect(page.locator('.file-preview-toolbar')).toContainText('Page 1 of 1');await expect(page.getByText('Loading page…')).toHaveCount(0);
 for(const [type,extension]of [['image/png','png'],['image/jpeg','jpg'],['image/webp','webp']]){const data=extension==='webp'?[...webpFixture()]:await page.evaluate(async type=>{const canvas=document.createElement('canvas');canvas.width=10;canvas.height=10;const context=canvas.getContext('2d')!;context.fillStyle='#176b50';context.fillRect(0,0,10,10);const blob=await new Promise<Blob>(resolve=>canvas.toBlob(value=>resolve(value!),type));return [...new Uint8Array(await blob.arrayBuffer())];},type!);
  await mount(page,'checked.'+extension,new Uint8Array(data));await expect(page.locator('.file-image-preview canvas')).toBeVisible();await expect(page.locator('.file-image-preview .spinner')).toHaveCount(0);expect(await page.locator('.file-image-preview canvas').getAttribute('width')).toBe('10');
 }
});
test('Dishonest compressed sizes, unsupported files and oversized encoded images use a safe working fallback',async({page})=>{
 await page.goto('/preview-test');await page.waitForFunction(()=>typeof(window as unknown as {previewFile:unknown}).previewFile==='function');
 await mount(page,'dishonest.docx',dishonestDocxFixture());await expect(page.getByRole('heading',{name:'Open the original to see this file'})).toBeVisible();
 await mount(page,'unsupported.exe',new TextEncoder().encode('not a preview'));await expect(page.getByRole('heading',{name:'Open the original to see this file'})).toBeVisible();
 const png=new Uint8Array(24);png.set([137,80,78,71,13,10,26,10]);const view=new DataView(png.buffer);view.setUint32(16,20000);view.setUint32(20,20000);
 await mount(page,'huge.png',png);await expect(page.getByRole('heading',{name:'Open the original to see this file'})).toBeVisible();await expect(page.locator('iframe,canvas')).toHaveCount(0);
});
