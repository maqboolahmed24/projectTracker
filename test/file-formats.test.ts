import assert from 'node:assert/strict';
import test from 'node:test';
import {assertPreviewImageSize,officeDirectory,validateFileBytes,FileFormatError} from '../src/client/file-formats.js';
import {parseDocumentPreview} from '../src/client/file-preview-worker.js';
import {dishonestDocxFixture,docxFixture,previewFixtures} from './file-preview-fixtures.js';

test('Office validation checks actual streaming inflation, CRC and matching directories before document parsers',()=>{
 const valid=docxFixture();officeDirectory(valid,'docx');const unsafe=dishonestDocxFixture();
 assert.doesNotThrow(()=>officeDirectory(unsafe,'docx',false));assert.throws(()=>officeDirectory(unsafe,'docx'),FileFormatError);
 const corrupt=valid.slice();const view=new DataView(corrupt.buffer);for(let i=0;i+46<corrupt.length;i++)if(view.getUint32(i,true)===0x02014b50){view.setUint32(i+16,0,true);break;}
 assert.throws(()=>officeDirectory(corrupt,'docx'),FileFormatError);
 assert.throws(()=>validateFileBytes(valid,'pretend.exe'),FileFormatError);
});
test('Supported document previews render real Office and RTF samples locally and retain escaped spreadsheet/text content',async()=>{
 for(const fixture of await previewFixtures()){const preview=await parseDocumentPreview(fixture.bytes,fixture.filename);assert.ok((preview.kind==='html'?preview.html:preview.text).includes(fixture.text),fixture.filename);
  if(fixture.filename.endsWith('.xlsx'))assert.ok(preview.kind==='html'&&preview.html.includes('&lt;script&gt;'));
 }
});
test('Encoded image dimensions are bounded before a browser allocates decoded pixels',()=>{
 const bytes=new Uint8Array(24),view=new DataView(bytes.buffer);view.setUint32(16,20000);view.setUint32(20,20000);
 assert.throws(()=>assertPreviewImageSize(bytes,'huge.png'),FileFormatError);view.setUint32(16,16);view.setUint32(20,16);assert.doesNotThrow(()=>assertPreviewImageSize(bytes,'small.png'));
});
