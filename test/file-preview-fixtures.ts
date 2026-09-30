import { strToU8,zipSync } from 'fflate';
import * as XLSX from 'xlsx';
import {addBlankSlide,addSlideTextBox,createPresentation,inches,savePresentation} from '@office-kit/pptx';

// A real 10 × 10 WebP: Safari decodes WebP but canvas.toBlob cannot encode it.
export const webpFixture=()=>new Uint8Array(Buffer.from('UklGRhICAABXRUJQVlA4WAoAAAAgAAAACQAACQAASUNDUMgBAAAAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADZWUDggJAAAAFABAJ0BKgoACgABQCYloAAEM4AA/vIh3//5gn/v9/3+8lwAAA==','base64'));

export function docxFixture(text='Preview document'){
 return zipSync({'[Content_Types].xml':strToU8('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'),
  '_rels/.rels':strToU8('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'),
  'word/document.xml':strToU8('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'+text+'</w:t></w:r></w:p></w:body></w:document>')},{level:6});
}
export function dishonestDocxFixture(){const bytes=docxFixture('A'.repeat(600000)),view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
 for(let offset=0;offset+46<bytes.length;offset++)if(view.getUint32(offset,true)===0x02014b50){const local=view.getUint32(offset+42,true),nameLength=view.getUint16(offset+28,true),name=new TextDecoder().decode(bytes.subarray(offset+46,offset+46+nameLength));
  if(name==='word/document.xml'){view.setUint32(offset+24,1,true);view.setUint32(local+22,1,true);return bytes;}}
 throw new Error('Fixture directory missing');
}
export async function previewFixtures(){
 const book=XLSX.utils.book_new();XLSX.utils.book_append_sheet(book,XLSX.utils.aoa_to_sheet([['Preview sheet',42],['Second row','<script>window.previewInjected=true</script>']]),'Review');
 const presentation=createPresentation(),slide=addBlankSlide(presentation);addSlideTextBox(slide,{x:inches(1),y:inches(1),w:inches(7),h:inches(1),text:'Preview slide'});
 return [
  {filename:'checked.docx',bytes:docxFixture(),text:'Preview document'},
  {filename:'checked.xlsx',bytes:new Uint8Array(XLSX.write(book,{type:'array',bookType:'xlsx',compression:true})),text:'Preview sheet'},
  {filename:'checked.pptx',bytes:await savePresentation(presentation),text:'Preview slide'},
  {filename:'checked.rtf',bytes:strToU8('{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Arial;}}\\f0\\fs24 Preview rich text\\par}'),text:'Preview rich text'},
  {filename:'checked.txt',bytes:strToU8('Preview text\n<script>window.previewInjected=true</script>'),text:'Preview text'},
  {filename:'checked.csv',bytes:strToU8('Name,Value\nPreview CSV,42'),text:'Preview CSV'},
 ];
}
export function pdfFixture(){let document='%PDF-1.4\n',offsets=[0];const objects=[
 '<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
 '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 220 160] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
 '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'];
 const content='BT /F1 14 Tf 20 90 Td (Preview PDF) Tj ET';objects.push('<< /Length '+content.length+' >>\nstream\n'+content+'\nendstream');
 for(let i=0;i<objects.length;i++){offsets.push(document.length);document+=(i+1)+' 0 obj\n'+objects[i]+'\nendobj\n';}
 const xref=document.length;document+='xref\n0 6\n0000000000 65535 f \n'+offsets.slice(1).map(offset=>String(offset).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+xref+'\n%%EOF';return strToU8(document);
}
