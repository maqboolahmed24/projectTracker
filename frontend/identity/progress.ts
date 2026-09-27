/** Cosmetic completion markers only. Never used as evidence of account or device authority. */
const key='ukda.ui.completed-setup.v1';
function read():string[]{try{const v:unknown=JSON.parse(localStorage.getItem(key)??'[]');return Array.isArray(v)?v.filter((x):x is string=>typeof x==='string'&&/^(activation|join|reset|phrase|promote|password|pair):[0-9a-f-]{36}$/.test(x)).slice(-128):[];}catch{return [];}}
export function wasFinished(kind:string,id:string):boolean{return read().includes(`${kind}:${id}`);}
export function rememberFinished(kind:string,id:string):void{try{localStorage.setItem(key,JSON.stringify([...new Set([...read(),`${kind}:${id}`])].slice(-128)));}catch{/* Storage preferences do not affect verified access. */}}
