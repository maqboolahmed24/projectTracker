'use client';
import { useEffect,useRef } from 'react';
import { ChevronDown } from 'lucide-react';
export function FilesMenu({actions}:{actions:{label:string;onClick:()=>void;disabled?:boolean}[]}){
 const ref=useRef<HTMLDetailsElement>(null);useEffect(()=>{const close=(event:PointerEvent)=>{if(ref.current&&!ref.current.contains(event.target as Node))ref.current.open=false;},key=(event:KeyboardEvent)=>{if(event.key==='Escape'&&ref.current?.open){event.preventDefault();ref.current.open=false;ref.current.querySelector('summary')?.focus();}};document.addEventListener('pointerdown',close);document.addEventListener('keydown',key);return()=>{document.removeEventListener('pointerdown',close);document.removeEventListener('keydown',key);};},[]);
 return <details ref={ref} className="files-more"><summary className="button button-secondary">More <ChevronDown size={14}/></summary><div className="files-more-menu">{actions.map(action=><button type="button" key={action.label} disabled={action.disabled} onClick={()=>{if(ref.current)ref.current.open=false;action.onClick();}}>{action.label}</button>)}</div></details>;
}
