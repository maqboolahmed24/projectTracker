/// <reference path="../types/mammoth-browser.d.ts" />
/// <reference path="../types/rtf-bundle.d.ts" />
import { validateFileBytes,PREVIEW_OFFICE_MAX_BYTES,PREVIEW_TEXT_MAX_BYTES } from './file-formats.js';
const escape=(s:unknown)=>String(s??'').replace(/[&<>"']/gu,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
export type DocumentPreview={kind:'html';html:string;note:string}|{kind:'text';text:string;note:string};
/** A disposable worker runs bounded local parsers. It has no document-network access. */
export async function parseDocumentPreview(bytes:Uint8Array,filename:string):Promise<DocumentPreview>{
  const ext=validateFileBytes(bytes,filename);
  if(['txt','csv'].includes(ext)){
    if(bytes.length>PREVIEW_TEXT_MAX_BYTES)throw new Error('PREVIEW_LIMIT');
    return {kind:'text',text:new TextDecoder('utf-8',{fatal:true}).decode(bytes),note:''};
  }
  if(bytes.length>PREVIEW_OFFICE_MAX_BYTES)throw new Error('PREVIEW_LIMIT');
  if(ext==='docx'){
    const {default:mammoth}=await import('mammoth/mammoth.browser.js');
    const result=await mammoth.convertToHtml({arrayBuffer:bytes.slice().buffer},{externalFileAccess:false,includeEmbeddedStyleMap:false,
      convertImage:mammoth.images.imgElement(async()=>({src:'',alt:'Image — open the original to view'}))});
    if(result.value.length>2*1024*1024)throw new Error('PREVIEW_LIMIT');
    return {kind:'html',html:result.value,note:'Preview may differ from the original. Embedded pictures are omitted.'};
  }
  if(ext==='xlsx'){
    const XLSX=await import('xlsx'),book=XLSX.read(bytes,{type:'array',sheetRows:201,cellHTML:false,cellFormula:false,cellStyles:false,bookVBA:false});
    const sections=book.SheetNames.slice(0,10).map(name=>{
      const sheet=book.Sheets[name];if(!sheet?.['!ref'])return `<h2>${escape(name)}</h2><p>Empty sheet</p>`;
      const range=XLSX.utils.decode_range(sheet['!ref']),rows=Math.min(200,range.e.r+1),cols=Math.min(50,range.e.c+1);let html=`<h2>${escape(name)}</h2><table><thead><tr><th></th>`;
      for(let c=0;c<cols;c++)html+=`<th>${XLSX.utils.encode_col(c)}</th>`;html+='</tr></thead><tbody>';
      for(let r=0;r<rows;r++){html+=`<tr><th>${r+1}</th>`;for(let c=0;c<cols;c++){const cell=sheet[XLSX.utils.encode_cell({r,c})];html+=`<td>${escape(cell?.w??cell?.v??'')}</td>`;}html+='</tr>';}
      return html+'</tbody></table>';
    });const html=sections.join('');if(html.length>2*1024*1024)throw new Error('PREVIEW_LIMIT');
    return {kind:'html',html,note:'Preview shows up to 10 sheets, 200 rows and 50 columns per sheet. Formulas are not recalculated.'};
  }
  if(ext==='rtf'){
    const {parseHTML}=await import('linkedom'),environment=parseHTML('<html><body></body></html>');
    Object.assign(globalThis,{document:environment.document,window:environment,DOMParser:environment.DOMParser});
    // The package's ESM entry uses extension-less imports which fail in Node.
    // The published UMD bundle supports both the disposable browser worker and our fixtures.
    const {default:RTFJS}=await import('rtf.js/dist/RTFJS.bundle.js');RTFJS.loggingEnabled(false);
    const doc=new RTFJS.Document(bytes.slice().buffer,{onPicture:()=>environment.document.createElement('span') as unknown as HTMLElement,
      onImport:(_url,done)=>done({error:new Error('External content unavailable')}),
      onHyperlink:(create)=>{const element=create();return {element,content:element};}});
    const elements=await doc.render(),html=elements.map(e=>e.outerHTML).join('');if(html.length>2*1024*1024)throw new Error('PREVIEW_LIMIT');
    return {kind:'html',html,note:'Preview may differ from the original. Embedded pictures are omitted.'};
  }
  if(ext==='pptx'){
    const {loadPresentation,getSlides}=await import('@office-kit/pptx'),{renderSlideToSvg}=await import('@office-kit/pptx-preview'),{parseHTML}=await import('linkedom'),pres=await loadPresentation(bytes);
    const slides=getSlides(pres);if(slides.length>100)throw new Error('PREVIEW_LIMIT');
    // Office Kit uses foreignObject for text; our sandbox deliberately forbids it.
    // Preserve readable slide text as inert SVG text, retaining safe coordinates only.
    const safeSlide=(svg:string)=>svg.replace(/<foreignObject\b([^>]*)>([\s\S]*?)<\/foreignObject>/gu,(_all,attributes:string,html:string)=>{
      const document=parseHTML(`<html><body>${html}</body></html>`).document,paragraphs=[...document.querySelectorAll('p')].map(p=>p.textContent??'');
      const coordinate=(name:string)=>{const value=Number(new RegExp(`\\b${name}="([+\\-\\d.]+)"`,'u').exec(attributes)?.[1]??0);return Number.isFinite(value)?value:0;};
      const x=coordinate('x'),y=coordinate('y')+20,lines=paragraphs.length?paragraphs:[document.body.textContent??''];
      return `<text x="${x}" y="${y}" font-size="20" fill="#24272b">${lines.map((line,index)=>`<tspan x="${x}" dy="${index?24:0}">${escape(line)}</tspan>`).join('')}</text>`;
    });
    const html=slides.slice(0,30).map((slide,index)=>`<section class="slide"><p>Slide ${index+1}</p>${safeSlide(renderSlideToSvg(pres,slide))}</section>`).join('');
    if(html.length>2*1024*1024)throw new Error('PREVIEW_LIMIT');return {kind:'html',html,note:'Preview shows up to 30 slides. Pictures are omitted and some formatting and effects may differ from the original.'};
  }
  throw new Error('PREVIEW_UNSUPPORTED');
}
const scope=globalThis as unknown as {postMessage?:(v:unknown)=>void;onmessage:((e:MessageEvent)=>void)|null;fetch:typeof fetch};
// Exported parser is also testable in Node; worker registration only runs on the worker surface.
if(typeof globalThis.document==='undefined'&&typeof (globalThis as {importScripts?:unknown}).importScripts==='function'){
  scope.fetch=()=>Promise.reject(new Error('Document network access is disabled'));
  scope.onmessage=event=>{
    const input=event.data as {bytes:Uint8Array;filename:string};
    void parseDocumentPreview(input.bytes,input.filename).then(preview=>scope.postMessage?.({ok:true,preview}),()=>scope.postMessage?.({ok:false})).finally(()=>input.bytes.fill(0));
  };
}
