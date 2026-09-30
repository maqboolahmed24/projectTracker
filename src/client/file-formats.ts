import { FILE_MAX_PLAIN_BYTES,FILE_SUPPORTED_EXTENSIONS } from '../shared/files.js';
import { Inflate } from 'fflate';
export const PREVIEW_OFFICE_MAX_BYTES=5*1024*1024,PREVIEW_TEXT_MAX_BYTES=2*1024*1024;
export class FileFormatError extends Error {constructor(readonly code:'UNSUPPORTED_FORMAT'|'UNSAFE_FORMAT'|'TOO_LARGE'){super(code);}}
export const extension=(filename:string)=>filename.split('.').at(-1)?.toLowerCase()??'';
const ascii=(b:Uint8Array,start=0,end=b.length)=>new TextDecoder().decode(b.subarray(start,end));
const crcTable=Uint32Array.from({length:256},(_,value)=>{for(let bit=0;bit<8;bit++)value=value&1?0xedb88320^(value>>>1):value>>>1;return value>>>0;});
const fail=():never=>{throw new FileFormatError('UNSAFE_FORMAT');};
/** Validate the complete directory before an Office parser can inflate any data. */
export function officeDirectory(bytes:Uint8Array,ext:string,verifyInflation=true):void{
  const view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);let end=-1;
  for(let i=bytes.length-22;i>=Math.max(0,bytes.length-65557);i--)if(view.getUint32(i,true)===0x06054b50){end=i;break;}
  if(end<0||view.getUint16(end+4,true)||view.getUint16(end+6,true)||view.getUint16(end+8,true)!==view.getUint16(end+10,true))throw new FileFormatError('UNSAFE_FORMAT');
  const count=view.getUint16(end+10,true),length=view.getUint32(end+12,true),start=view.getUint32(end+16,true);
  if(!count||count>2000||start+length>end||end+22+view.getUint16(end+20,true)!==bytes.length)throw new FileFormatError('UNSAFE_FORMAT');
  const paths=new Set<string>(),ranges:{start:number;end:number}[]=[];let offset=start,total=0,actualTotal=0;
  for(let i=0;i<count;i++){
    if(offset+46>start+length||view.getUint32(offset,true)!==0x02014b50)throw new FileFormatError('UNSAFE_FORMAT');
    const flags=view.getUint16(offset+8,true),method=view.getUint16(offset+10,true),packed=view.getUint32(offset+20,true),size=view.getUint32(offset+24,true),
      nameLength=view.getUint16(offset+28,true),extra=view.getUint16(offset+30,true),comment=view.getUint16(offset+32,true),local=view.getUint32(offset+42,true),next=offset+46+nameLength+extra+comment;
    if(next>start+length||flags&~0x80e||![0,8].includes(method)||local+30>start||size>16*1024*1024||size>Math.max(4096,packed*100)||view.getUint32(local,true)!==0x04034b50)throw new FileFormatError('UNSAFE_FORMAT');
    const name=ascii(bytes,offset+46,offset+46+nameLength);
    if(!name||name.includes('\\')||name.startsWith('/')||/^[a-z]:/iu.test(name)||name.split('/').some(p=>p==='..'||p==='.'||['__proto__','constructor','prototype'].includes(p.toLowerCase()))||/[\u0000-\u001f\u007f]/u.test(name)||paths.has(name))throw new FileFormatError('UNSAFE_FORMAT');
    const localName=view.getUint16(local+26,true),localExtra=view.getUint16(local+28,true),dataStart=local+30+localName+localExtra;
    if(dataStart+packed>start||ascii(bytes,local+30,local+30+localName)!==name||view.getUint16(local+6,true)!==flags||view.getUint16(local+8,true)!==method||
      ranges.some(range=>local<range.end&&dataStart+packed>range.start))throw new FileFormatError('UNSAFE_FORMAT');
    ranges.push({start:local,end:dataStart+packed});
    if(verifyInflation){let actual=0,crc=0xffffffff,finished=false;
      const check=(chunk:Uint8Array,final:boolean)=>{actual+=chunk.length;actualTotal+=chunk.length;
        if(actual>size||actual>16*1024*1024||actualTotal>80*1024*1024)fail();
        for(const value of chunk)crc=crcTable[(crc^value)&255]!^(crc>>>8);finished=final;
      };
      try{if(method===0){if(packed!==size)fail();check(bytes.subarray(dataStart,dataStart+packed),true);}
        else{const inflater=new Inflate((chunk,final)=>{try{check(chunk,final);}finally{chunk.fill(0);}});
          if(!packed)fail();for(let n=0;n<packed;n+=256)inflater.push(bytes.subarray(dataStart+n,dataStart+Math.min(packed,n+256)),n+256>=packed);}
        if(!finished||actual!==size||((crc^0xffffffff)>>>0)!==view.getUint32(offset+16,true))fail();
      }catch{fail();}
    }
    paths.add(name);total+=size;if(total>80*1024*1024)throw new FileFormatError('UNSAFE_FORMAT');offset=next;
  }
  if(offset!==start+length||!paths.has('[Content_Types].xml')||!paths.has(ext==='docx'?'word/document.xml':ext==='xlsx'?'xl/workbook.xml':'ppt/presentation.xml'))throw new FileFormatError('UNSAFE_FORMAT');
  if([...paths].some(p=>/vbaProject|activeX|embeddings\/|\.exe$/iu.test(p)))throw new FileFormatError('UNSAFE_FORMAT');
}
export function validateFileBytes(bytes:Uint8Array,filename:string,options:{verifyInflation?:boolean}={}):string{
  const ext=extension(filename);if(!FILE_SUPPORTED_EXTENSIONS.includes(ext as typeof FILE_SUPPORTED_EXTENSIONS[number]))throw new FileFormatError('UNSUPPORTED_FORMAT');
  if(!bytes.length||bytes.length>FILE_MAX_PLAIN_BYTES)throw new FileFormatError('TOO_LARGE');
  if(['docx','xlsx','pptx'].includes(ext)){officeDirectory(bytes,ext,options.verifyInflation!==false);return ext;}
  const first=ascii(bytes,0,Math.min(bytes.length,1024));
  const valid=ext==='pdf'?first.startsWith('%PDF-'):ext==='rtf'?first.trimStart().startsWith('{\\rtf'):
    ext==='png'?bytes.subarray(0,8).join(',')==='137,80,78,71,13,10,26,10':
    ['jpg','jpeg'].includes(ext)?bytes[0]===255&&bytes[1]===216&&bytes[2]===255:
    ext==='webp'?ascii(bytes,0,4)==='RIFF'&&ascii(bytes,8,12)==='WEBP':!bytes.subarray(0,1024).includes(0);
  if(!valid)throw new FileFormatError('UNSAFE_FORMAT');return ext;
}
/** Read encoded dimensions before a browser decoder allocates an image canvas. */
export function assertPreviewImageSize(bytes:Uint8Array,filename:string):void{
  const ext=extension(filename),view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);let width=0,height=0;
  if(ext==='png'&&bytes.length>=24){width=view.getUint32(16);height=view.getUint32(20);}
  else if(['jpg','jpeg'].includes(ext)){for(let offset=2;offset+4<bytes.length;){if(bytes[offset]!==255)fail();const marker=bytes[offset+1]!;if(marker===0xd9||marker===0xda)break;
    const length=view.getUint16(offset+2);if(length<2||offset+2+length>bytes.length)fail();
    if([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(marker)){if(length<7)fail();height=view.getUint16(offset+5);width=view.getUint16(offset+7);break;}offset+=2+length;}}
  else if(ext==='webp'&&bytes.length>=30){const type=ascii(bytes,12,16);
    if(type==='VP8X'){width=1+bytes[24]!+(bytes[25]!<<8)+(bytes[26]!<<16);height=1+bytes[27]!+(bytes[28]!<<8)+(bytes[29]!<<16);}
    else if(type==='VP8 '&&bytes[23]===0x9d&&bytes[24]===0x01&&bytes[25]===0x2a){width=view.getUint16(26,true)&0x3fff;height=view.getUint16(28,true)&0x3fff;}
    else if(type==='VP8L'&&bytes[20]===0x2f){const bits=view.getUint32(21,true);width=1+(bits&0x3fff);height=1+((bits>>>14)&0x3fff);}
  }
  if(width<1||height<1||width>8192||height>8192||width*height>20_000_000)throw new FileFormatError('TOO_LARGE');
}
export async function validateSelectedManagedFile(file:Blob,filename:string):Promise<void>{
  if(file.size>FILE_MAX_PLAIN_BYTES||file.size<1)throw new FileFormatError('TOO_LARGE');
  const bytes=new Uint8Array(await file.arrayBuffer());try{validateFileBytes(bytes,filename);}finally{bytes.fill(0);}
}
