'use client';
import { createContext, useContext, useEffect, useId, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type TextareaHTMLAttributes, type SelectHTMLAttributes, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { AlertCircle, LoaderCircle, X, ArrowRight, Maximize2, Minimize2 } from 'lucide-react';
import type { AvatarSelection } from '../../src/shared/avatar.js';
import { customerError } from './errors';
import './choice.css';
export function Spinner(){return <LoaderCircle className="spinner" size={18} aria-label="Loading"/>;}
export function Button({variant='primary',busy=false,className='',children,disabled,type='button',...props}:ButtonHTMLAttributes<HTMLButtonElement>&{variant?:'primary'|'secondary'|'ghost'|'danger';busy?:boolean}){return <button {...props} type={type} disabled={disabled||busy} aria-busy={busy} className={`button button-${variant} ${className}`}>{children}{busy&&<LoaderCircle className="spinner button-spinner" size={18} aria-hidden="true"/>}</button>;}
const FieldContext=createContext<{labelId:string;descriptionId:string|undefined;invalid:boolean}|null>(null);
function useFieldAttributes(){const field=useContext(FieldContext);return field?{'aria-labelledby':field.labelId,'aria-describedby':field.descriptionId,'aria-invalid':field.invalid}:{};}
export function Input(props:InputHTMLAttributes<HTMLInputElement>){const field=useFieldAttributes();return <input {...field} {...props} data-dialog-autofocus={props.autoFocus||undefined} className={`input ${props.className??''}`}/>;}
export function Textarea(props:TextareaHTMLAttributes<HTMLTextAreaElement>){const field=useFieldAttributes();return <textarea rows={4} {...field} {...props} data-dialog-autofocus={props.autoFocus||undefined} className={`input textarea ${props.className??''}`}/>;}
export function Select(props:SelectHTMLAttributes<HTMLSelectElement>){const field=useFieldAttributes();return <select {...field} {...props} data-dialog-autofocus={props.autoFocus||undefined} className={`input select ${props.className??''}`}/>;}
export function Field({label,hint,error,children,group=false}:{label:ReactNode;hint?:ReactNode;error?:ReactNode;children:ReactNode;group?:boolean}){const id=useId(),descriptionId=[hint?id+'-hint':'',error?id+'-error':''].filter(Boolean).join(' ')||undefined,Control=group?'div':'label';return <FieldContext.Provider value={{labelId:id,descriptionId,invalid:!!error}}><div className="field"><Control className="field-control"><span id={id} className="field-label">{label}</span>{children}</Control>{hint&&<span id={id+'-hint'} className="field-hint">{hint}</span>}{error&&<span id={id+'-error'} className="field-error" role="alert">{error}</span>}</div></FieldContext.Provider>;}
/** Expose a short set of choices without replacing native radio keyboard behavior.
 * Wrap in <Field group> so the group has one label and each option keeps its own. */
export function ChoiceGroup({value,onChange,options,name,disabled=false,autoFocus=false,...props}:{value:string;onChange:(value:string)=>void;options:readonly {value:string;label:string;disabled?:boolean}[];name?:string;disabled?:boolean;autoFocus?:boolean;'aria-label'?:string}){
  const id=useId(),field=useFieldAttributes(),focusValue=options.find(option=>option.value===value&&!option.disabled)?.value??options.find(option=>!option.disabled)?.value;
  return <div {...field} {...props} role="radiogroup" className="choice-group" aria-disabled={disabled||undefined}>{options.map(option=><label key={option.value} className="choice-option" data-selected={value===option.value} data-disabled={disabled||option.disabled||undefined}><input type="radio" name={name??id} value={option.value} checked={value===option.value} disabled={disabled||option.disabled} onChange={()=>onChange(option.value)} autoFocus={autoFocus&&option.value===focusValue} data-dialog-autofocus={autoFocus&&option.value===focusValue||undefined}/><span>{option.label}</span></label>)}</div>;
}
export type BadgeTone = 'neutral'|'success'|'warning'|'danger'|'info'|'purple';
export function Badge({tone='neutral',children}:{tone?:BadgeTone;children:ReactNode}){return <span className={`badge badge-${tone}`}>{children}</span>;}
export function PageHead({title,description,eyebrow,actions}:{title:string;description?:ReactNode;eyebrow?:string;actions?:ReactNode}){return <header className="page-header"><div>{eyebrow&&<p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1>{description&&<p className="page-description">{description}</p>}</div>{actions&&<div className="page-actions">{actions}</div>}</header>;}
export function EmptyState({title,description,action,icon}:{title:string;description:ReactNode;action?:ReactNode;icon?:ReactNode}){return <div className="empty-state">{icon&&<div className="empty-icon">{icon}</div>}<h2>{title}</h2><p>{description}</p>{action}</div>;}
export function ErrorNotice({error,retry}:{error:unknown;retry?:()=>void}){return <div className="notice notice-error" role="alert"><AlertCircle size={19}/><span>{customerError(error)}</span>{retry&&<Button variant="ghost" onClick={retry}>Try again <ArrowRight size={16}/></Button>}</div>;}
const openDialogs:HTMLDialogElement[]=[];
let previousOverflow='';
export function Modal({open,onClose,title,description,children,footer,navigation,layout='content',scrollKey,expandable=false}:{open:boolean;onClose:()=>void;title:string;description?:ReactNode;children:ReactNode;footer?:ReactNode;navigation?:ReactNode;layout?:'content'|'detail'|'form';scrollKey?:string;expandable?:boolean}){
  const ref=useRef<HTMLDialogElement>(null),body=useRef<HTMLDivElement>(null),heading=useId(),[mounted,setMounted]=useState(false),[expanded,setExpanded]=useState(false);
  useEffect(()=>setMounted(true),[]);
  useEffect(()=>{
    const dialog=ref.current;if(!open||!dialog)return;
    const previous=document.activeElement as HTMLElement|null;
    dialog.showModal();
    // React mounts portal inputs before the native dialog becomes focusable.
    dialog.querySelector<HTMLElement>('[data-dialog-autofocus="true"]:not(:disabled)')?.focus({preventScroll:true});
    if(!openDialogs.length){previousOverflow=document.documentElement.style.overflow;document.documentElement.style.overflow='hidden';}
    openDialogs.push(dialog);
    return()=>{
      const wasTop=openDialogs.at(-1)===dialog;
      const index=openDialogs.indexOf(dialog);if(index>=0)openDialogs.splice(index,1);
      if(dialog.open)dialog.close();
      if(!openDialogs.length)document.documentElement.style.overflow=previousOverflow;
      const top=openDialogs.at(-1);
      if(wasTop&&previous?.isConnected&&(!top||top.contains(previous)))previous.focus({preventScroll:true});
    };
  },[open,mounted]);
  useEffect(()=>{if(body.current)body.current.scrollTop=0;},[scrollKey,open]);
  useEffect(()=>{if(!open)setExpanded(false);},[open]);
  if(!open||!mounted)return null;
  return createPortal(<dialog ref={ref} className={`modal modal-${layout}${expanded?' modal-expanded':''}`} aria-labelledby={heading} onCancel={event=>{event.preventDefault();if(expanded)setExpanded(false);else onClose();}} onClick={event=>{if(event.target===event.currentTarget){const r=event.currentTarget.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)onClose();}}}><div className="modal-header"><div><h2 id={heading}>{title}</h2>{description&&<p className="muted">{description}</p>}</div><div className="modal-header-actions">{expandable&&<Button variant="ghost" aria-label={expanded?'Restore window size':'Expand window'} title={expanded?'Restore window size':'Expand window'} aria-pressed={expanded} onClick={()=>setExpanded(value=>!value)}>{expanded?<Minimize2 size={19}/>:<Maximize2 size={19}/>}</Button>}<Button variant="ghost" aria-label="Close dialog" title="Close" onClick={onClose}><X size={20}/></Button></div></div>{navigation&&<div className="modal-navigation">{navigation}</div>}<div ref={body} className="modal-body" role="region" aria-labelledby={heading} tabIndex={0}>{children}</div>{footer&&<div className="modal-footer">{footer}</div>}</dialog>,document.body);
}
export function DialogTabs({id,label,value,tabs,onChange}:{id:string;label:string;value:string;tabs:readonly {id:string;label:string}[];onChange:(value:string)=>void}){
  return <div className="tabs" role="tablist" aria-label={label}>{tabs.map((tab,index)=><button type="button" key={tab.id} id={`${id}-tab-${tab.id}`} role="tab" aria-selected={value===tab.id} aria-controls={`${id}-panel-${tab.id}`} tabIndex={value===tab.id?0:-1} onClick={()=>onChange(tab.id)} onKeyDown={event=>{const next=event.key==='ArrowRight'?(index+1)%tabs.length:event.key==='ArrowLeft'?(index+tabs.length-1)%tabs.length:event.key==='Home'?0:event.key==='End'?tabs.length-1:null;if(next===null)return;event.preventDefault();onChange(tabs[next]!.id);document.getElementById(`${id}-tab-${tabs[next]!.id}`)?.focus();}}>{tab.label}</button>)}</div>;
}
export interface AvatarCatalogue {defaultSelection:AvatarSelection;shapes:{id:AvatarSelection['shapeId'];label:string;svg:string}[];colours:{id:AvatarSelection['colourId'];label:string;hex:string}[]}
let cataloguePromise:Promise<AvatarCatalogue>|undefined;
export function getAvatarCatalogue(){return cataloguePromise??=(async()=>{const response=await fetch('/v1/avatars/catalog',{credentials:'omit'});if(!response.ok)throw new Error('AVATAR_UNAVAILABLE');return response.json() as Promise<AvatarCatalogue>;})().catch(error=>{cataloguePromise=undefined;throw error;});}
export function Avatar({selection,name,size=36}:{selection?:AvatarSelection|undefined;name:string;size?:number}){
  const [catalogue,setCatalogue]=useState<AvatarCatalogue>();
  useEffect(()=>{let active=true;void getAvatarCatalogue().then(value=>{if(active)setCatalogue(value);}).catch(()=>{});return()=>{active=false;};},[]);
  const picked=selection??catalogue?.defaultSelection,shape=catalogue?.shapes.find(value=>value.id===picked?.shapeId),colour=catalogue?.colours.find(value=>value.id===picked?.colourId);
  const src=shape&&colour&&/^#[a-f\d]{6}$/i.test(colour.hex)?'data:image/svg+xml;charset=utf-8,'+encodeURIComponent(shape.svg.replaceAll('currentColor',colour.hex)):undefined;
  return <span className="avatar" style={{width:size,height:size}} title={name}>{src?<img src={src} alt={name} width={size} height={size}/>:<span aria-label={name}>{name.trim().slice(0,1).toUpperCase()}</span>}</span>;
}
