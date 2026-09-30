'use client';
import { useEffect,useRef,useState } from 'react';
import DOMPurify from 'dompurify';
import { ChevronLeft,ChevronRight,FileSearch } from 'lucide-react';
import { Button,Spinner } from '../shared/ui';
import { assertPreviewImageSize,extension,validateFileBytes } from '../../src/client/file-formats.js';
import type { DocumentPreview } from '../../src/client/file-preview-worker.js';
import './preview.css';

const previewStyle=`body{margin:0;padding:30px;background:#fff;color:#24272b;font:15px/1.6 system-ui,sans-serif;overflow-wrap:anywhere}h1,h2,h3{line-height:1.25}table{border-collapse:collapse;font-size:13px;white-space:nowrap;max-width:100%}th,td{border:1px solid #e4e7e9;padding:8px 12px;text-align:left}th{background:#f6f7f8}section.slide{margin-bottom:28px}svg{max-width:100%;height:auto}a{color:inherit;text-decoration:none}img{max-width:100%}`;
function OfficePreview({bytes,filename}:{bytes:Uint8Array;filename:string}){
  const [preview,setPreview]=useState<DocumentPreview>(),[failed,setFailed]=useState(false);
  useEffect(()=>{setPreview(undefined);setFailed(false);const worker=new Worker('/client/file-preview-worker.js',{type:'module'});
    const timeout=window.setTimeout(()=>{worker.terminate();setFailed(true);},15000);
    worker.onmessage=event=>{clearTimeout(timeout);worker.terminate();const result=event.data as {ok:boolean;preview?:DocumentPreview};if(result.ok&&result.preview)setPreview(result.preview);else setFailed(true);};
    worker.onerror=()=>{clearTimeout(timeout);worker.terminate();setFailed(true);};
    const copy=bytes.slice();worker.postMessage({bytes:copy,filename},[copy.buffer]);return()=>{clearTimeout(timeout);worker.terminate();};
  },[bytes,filename]);
  if(failed)return <PreviewFallback/>;if(!preview)return <div className="file-preview-wait"><Spinner/><span>Preparing your preview…</span></div>;
  if(preview.kind==='text')return <pre className="file-text-preview">{preview.text}</pre>;
  const sanitized=DOMPurify.sanitize(preview.html,{USE_PROFILES:{html:true,svg:true},FORBID_TAGS:['script','style','iframe','object','embed','form','input','button','audio','video','foreignObject','image','use','animate','set'],
    FORBID_ATTR:['href','xlink:href','src','srcset','style','id','name'],ALLOW_DATA_ATTR:false});
  const srcDoc=`<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><style>${previewStyle}</style></head><body>${sanitized}</body></html>`;
  return <div className="file-document-preview"><iframe title={`Preview of ${filename}`} sandbox="" srcDoc={srcDoc}/>{preview.note&&<p className="file-preview-note">{preview.note}</p>}</div>;
}
function PreviewFallback(){return <div className="file-preview-fallback"><FileSearch size={30}/><h3>Open the original to see this file</h3><p>A safe preview isn’t available here. You can download it if your role allows, or open the file on your shared drive.</p></div>;}
function ImagePreview({bytes,filename}:{bytes:Uint8Array;filename:string}){
  const canvas=useRef<HTMLCanvasElement>(null),[failed,setFailed]=useState(false),[loading,setLoading]=useState(true);
  useEffect(()=>{let cancelled=false;setFailed(false);setLoading(true);const data=bytes.slice();
    try{assertPreviewImageSize(data,filename);}catch{data.fill(0);setFailed(true);setLoading(false);return;}
    const timeout=window.setTimeout(()=>{cancelled=true;data.fill(0);setFailed(true);setLoading(false);},15000);
    void createImageBitmap(new Blob([data.buffer])).then(image=>{
      try{if(cancelled)return;if(image.width>8192||image.height>8192||image.width*image.height>20_000_000)throw new Error('Image too large');
        const element=canvas.current,context=element?.getContext('2d');if(!element||!context)throw new Error('Preview unavailable');element.width=image.width;element.height=image.height;context.drawImage(image,0,0);setLoading(false);
      }catch{if(!cancelled){setFailed(true);setLoading(false);}}finally{clearTimeout(timeout);image.close();data.fill(0);}
    },()=>{clearTimeout(timeout);data.fill(0);if(!cancelled){setFailed(true);setLoading(false);}});
    return()=>{clearTimeout(timeout);cancelled=true;const element=canvas.current;if(element){element.width=1;element.height=1;}};
  },[bytes,filename]);
  if(failed)return <PreviewFallback/>;return <div className="file-image-preview">{loading&&<Spinner/>}<canvas ref={canvas} role="img" aria-label={`Preview of ${filename}`}/></div>;
}
function PdfPreview({bytes,filename}:{bytes:Uint8Array;filename:string}){
  const canvas=useRef<HTMLCanvasElement>(null),[page,setPage]=useState(1),[total,setTotal]=useState(0),[loading,setLoading]=useState(true),[failed,setFailed]=useState(false);
  const documentRef=useRef<import('pdfjs-dist').PDFDocumentProxy|undefined>(undefined);
  useEffect(()=>{let cancelled=false;setFailed(false);setLoading(true);setPage(1);setTotal(0);
    let task:import('pdfjs-dist').PDFDocumentLoadingTask|undefined;
    const timeout=window.setTimeout(()=>{cancelled=true;setFailed(true);setLoading(false);if(task)void task.destroy();},15000);
    void import('pdfjs-dist').then(pdf=>{if(cancelled)return;pdf.GlobalWorkerOptions.workerSrc='/preview/pdf.worker.min.mjs';
      // Canvas-only rendering never instantiates PDF scripting, actions or annotation layers.
      task=pdf.getDocument({data:bytes.slice(),useSystemFonts:true,disableFontFace:true,enableXfa:false,disableAutoFetch:true,disableStream:true,stopAtErrors:true});
      return task.promise.then(doc=>{clearTimeout(timeout);if(cancelled){void task?.destroy();return;}if(doc.numPages>500){void task?.destroy();throw new Error('Preview limit');}documentRef.current=doc;setTotal(doc.numPages);});
    }).catch(()=>{clearTimeout(timeout);if(!cancelled){setFailed(true);setLoading(false);}});
    return()=>{clearTimeout(timeout);cancelled=true;documentRef.current=undefined;if(task)void task.destroy();const c=canvas.current;if(c){c.width=1;c.height=1;}};
  },[bytes]);
  useEffect(()=>{const doc=documentRef.current,element=canvas.current;if(!doc||!element)return;let cancelled=false,render:import('pdfjs-dist').RenderTask|undefined;
    const timeout=window.setTimeout(()=>{cancelled=true;render?.cancel();setFailed(true);setLoading(false);},15000);
    setLoading(true);void doc.getPage(page).then(sheet=>{if(cancelled)return;const view=sheet.getViewport({scale:1.25});if(view.width*view.height>12_000_000)throw new Error('Preview limit');
      element.width=Math.ceil(view.width);element.height=Math.ceil(view.height);const context=element.getContext('2d');if(!context)throw new Error('Preview unavailable');
      render=sheet.render({canvas:element,canvasContext:context,viewport:view});return render.promise.then(()=>{clearTimeout(timeout);sheet.cleanup();if(!cancelled)setLoading(false);});
    }).catch(()=>{clearTimeout(timeout);if(!cancelled){setFailed(true);setLoading(false);}});return()=>{clearTimeout(timeout);cancelled=true;render?.cancel();};
  },[page,total]);
  if(failed)return <PreviewFallback/>;
  return <div className="file-pdf-preview"><div className="file-preview-toolbar"><Button variant="ghost" aria-label="Previous page" disabled={page<=1||loading} onClick={()=>setPage(page-1)}><ChevronLeft size={18}/></Button><span>Page {page} of {total||'…'}</span><Button variant="ghost" aria-label="Next page" disabled={!total||page>=total||loading} onClick={()=>setPage(page+1)}><ChevronRight size={18}/></Button></div>{loading&&<div className="file-preview-wait"><Spinner/><span>Loading page…</span></div>}<canvas ref={canvas} role="img" aria-label={`${filename}, page ${page}`}/></div>;
}
export function FilePreview({bytes,filename}:{bytes:Uint8Array;filename:string}){
  // Heavy Office validation and parsing run in the disposable worker.
  try{validateFileBytes(bytes,filename,{verifyInflation:false});}catch{return <PreviewFallback/>;}
  const ext=extension(filename);return ext==='pdf'?<PdfPreview bytes={bytes} filename={filename}/>:
    ['png','jpg','jpeg','webp'].includes(ext)?<ImagePreview bytes={bytes} filename={filename}/>:<OfficePreview bytes={bytes} filename={filename}/>;
}
