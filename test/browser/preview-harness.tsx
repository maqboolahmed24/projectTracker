import React from 'react';
import {createRoot} from 'react-dom/client';
import {FilePreview} from '../../frontend/files/preview';
const element=document.createElement('main');document.body.append(element);const root=createRoot(element);
(window as unknown as {previewFile:(filename:string,bytes:number[])=>void}).previewFile=(filename,bytes)=>root.render(<FilePreview filename={filename} bytes={new Uint8Array(bytes)}/>);
