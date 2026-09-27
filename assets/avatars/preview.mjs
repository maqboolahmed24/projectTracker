// Review-only contact sheet; never served as a product screen.
import { readFile, writeFile } from 'node:fs/promises';
import { chromium } from 'playwright';
const manifest = JSON.parse(await readFile(new URL('./manifest.json', import.meta.url), 'utf8'));
const templates = await Promise.all(manifest.shapes.map(s => readFile(new URL(s.file, import.meta.url), 'utf8')));
const card = (svg, colour, label) => `<div class="card"><div class="portrait" style="color:${colour}">${svg}</div><div class="label">${label}</div></div>`;
const main = templates.map((svg, i) => card(svg, manifest.colours[i % 12].hex, `${manifest.shapes[i].id} · ${manifest.shapes[i].label}`)).join('');
const variants = manifest.colours.map((c, i) => card(templates[0].replaceAll('shape-01-', `variant-${i}-`), c.hex, c.label)).join('');
const small = templates.map((svg, i) => `<div style="width:36px;height:36px;color:${manifest.colours[i % 12].hex}">${svg.replaceAll(manifest.shapes[i].id+'-', 'small-'+i+'-')}</div>`).join('');
const html = `<!doctype html><html><head><meta charset="utf-8"><style>body{margin:0;padding:36px;background:#f4f2ed;color:#243247;font:14px -apple-system,BlinkMacSystemFont,sans-serif}h1{font-size:26px;letter-spacing:-.5px;margin:0 0 6px}p{margin:0 0 22px;color:#637080}h2{font-size:17px;margin:26px 0 12px}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}.card{border:1px solid #e6e2da;border-radius:14px;background:#fffefa;text-align:center;padding:8px 9px 11px}.portrait{width:142px;height:142px;margin:auto}.portrait svg{width:100%;height:100%}.label{font-size:11px;white-space:nowrap}.palette{display:grid;grid-template-columns:repeat(12,1fr);gap:6px}.palette .card{padding:4px 0 8px;border-radius:10px}.palette .portrait{width:66px;height:66px}.small{display:flex;justify-content:space-between;background:#fffefa;border-radius:12px;padding:10px}.small svg{width:100%;height:100%}footer{font-size:11px;color:#657180;margin-top:20px}</style></head><body><h1>Avatar collection</h1><p>20 illustrated shapes × 12 independent colours · 240 combinations</p><div class="grid">${main}</div><h2>One shape, all twelve colours</h2><div class="palette">${variants}</div><h2>Small profile size</h2><div class="small">${small}</div><footer>Critters by DiceBear · CC0 1.0 · Locally bundled SVG artwork; no upload or external avatar service.</footer></body></html>`;
const browser = await chromium.launch({headless:true, executablePath:process.env.AVATAR_REVIEW_BROWSER || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'});
try {
  const page = await browser.newPage({viewport:{width:1040,height:1100},deviceScaleFactor:1});
  await page.setContent(html);
  const validations = await page.evaluate((templates) => templates.map((svg) => {
    const doc = new DOMParser().parseFromString(svg,'image/svg+xml');
    return {xmlValid:!doc.querySelector('parsererror'),externalResources:doc.querySelectorAll('script,image,foreignObject,style,animate,animateTransform,use,text').length};
  }), templates);
  if(validations.some(v=>!v.xmlValid||v.externalResources))throw new Error('Invalid or active SVG content.');
  await page.screenshot({path:new URL('./preview.png',import.meta.url).pathname,fullPage:true});
  await writeFile(new URL('./preview-validation.json',import.meta.url),JSON.stringify({templates:validations.length,xmlValid:validations.every(v=>v.xmlValid),activeOrExternalElements:validations.reduce((n,v)=>n+v.externalResources,0)},null,2)+'\n');
  console.log('Rendered and XML-validated all 20 templates.');
} finally { await browser.close(); }
