import { spawn } from 'node:child_process';
import { stat } from 'node:fs/promises';
import { relative } from 'node:path';

// Python's standard-library openat operations keep directory descriptors open.
// No shell, path expansion or traversal through symbolic links is involved.
const program=String.raw`
import os,sys,json,hashlib,stat,uuid,base64
q=json.load(sys.stdin); root=os.open(q['root'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
fds=[root]
try:
 r=os.fstat(root)
 if str(r.st_dev)!=q['dev'] or str(r.st_ino)!=q['ino']: raise PermissionError('root changed')
 def parent(name,create=False):
  parts=name.split('/')
  if not parts or any(p in ('','.', '..') or '\\' in p or '\x00' in p for p in parts): raise PermissionError('invalid path')
  fd=root
  for part in parts[:-1]:
   if create:
    try: os.mkdir(part,0o700,dir_fd=fd);os.fsync(fd)
    except FileExistsError: pass
   fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
  return fd,parts[-1]
 def hashfile(name):
  fd,n=parent(name)
  try: f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
  except FileNotFoundError:return None
  try:
   before=os.fstat(f)
   if not stat.S_ISREG(before.st_mode) or before.st_size>2147483648:raise ValueError('invalid file')
   h=hashlib.sha256();count=0
   while True:
    b=os.read(f,262144)
    if not b:break
    count+=len(b)
    if count>2147483648:raise ValueError('large file')
    h.update(b)
   after=os.fstat(f)
   if count!=before.st_size or (after.st_size,after.st_mtime_ns)!=(before.st_size,before.st_mtime_ns):raise FileExistsError('changed file')
   return h.hexdigest()
  finally:os.close(f)
 op=q['op'];a=q['args'];result=None
 if op=='hash':result=hashfile(a['path'])
 elif op=='mkdir':
  fd,n=parent(a['path'],True)
  try:os.mkdir(n,0o700,dir_fd=fd);os.fsync(fd)
  except FileExistsError:pass
  d=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(d)
 elif op=='read':
  fd,n=parent(a['path']);f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
  try:
   b=os.read(f,262145)
   if len(b)>262144:raise ValueError('large metadata')
   result=b.decode('utf8')
  finally:os.close(f)
 elif op in ('write','json'):
  fd,n=parent(a['path']);temp=n+'.'+str(uuid.uuid4())+'.tmp' if op=='json' else n
  f=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
  try:
   b=a['text'].encode('utf8') if op=='json' else base64.urlsafe_b64decode(a['bytes']+'='*((-len(a['bytes']))%4))
   view=memoryview(b)
   while view:view=view[os.write(f,view):]
   os.fsync(f)
  finally:os.close(f)
  if op=='json':os.rename(temp,n,src_dir_fd=fd,dst_dir_fd=fd)
  os.fsync(fd)
 elif op in ('capture','link','copy'):
  sf,s=parent(a['source']);df,d=parent(a['destination'])
  if op=='capture':
   # Backup names are private and never reused; refuse unexpected collisions.
   try:os.stat(d,dir_fd=df,follow_symlinks=False);raise FileExistsError('backup exists')
   except FileNotFoundError:pass
   os.rename(s,d,src_dir_fd=sf,dst_dir_fd=df)
  elif op=='link':os.link(s,d,src_dir_fd=sf,dst_dir_fd=df,follow_symlinks=False)
  else:
   src=os.open(s,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=sf);out=os.open(d,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=df)
   try:
    if not stat.S_ISREG(os.fstat(src).st_mode):raise ValueError('invalid file')
    count=0
    while True:
     b=os.read(src,262144)
     if not b:break
     count+=len(b)
     if count>2147483648:raise ValueError('large file')
     v=memoryview(b)
     while v:v=v[os.write(out,v):]
    os.fsync(out)
   finally:os.close(src);os.close(out)
  os.fsync(sf);os.fsync(df)
 else:raise ValueError('invalid operation')
 print(json.dumps({'ok':True,'result':result}))
except Exception as e:
 print(json.dumps({'ok':False,'code':'ENOENT' if isinstance(e,FileNotFoundError) else 'EEXIST' if isinstance(e,FileExistsError) else 'ENOSPC' if isinstance(e,OSError) and e.errno==28 else 'UNSAFE'}))
finally:
 for fd in reversed(fds):os.close(fd)
`;
export class RootIO {
  private constructor(readonly root:string,private readonly dev:string,private readonly ino:string){}
  static async open(root:string){const s=await stat(root,{bigint:true});return new RootIO(root,String(s.dev),String(s.ino));}
  private path(path:string){const p=relative(this.root,path);if(!p||p.startsWith('../')||p.startsWith('/'))throw new Error('Unsafe local path');return p;}
  private async call(op:string,args:Record<string,string>):Promise<unknown>{return new Promise((resolve,reject)=>{
    const child=spawn('/usr/bin/python3',['-I','-c',program],{stdio:['pipe','pipe','pipe']}),out:Buffer[]=[];let size=0;
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('Local operation timed out'));},120000);
    child.stdout.on('data',(b:Buffer)=>{size+=b.length;if(size>512*1024)child.kill('SIGKILL');else out.push(b);});child.stderr.resume();
    child.on('error',error=>{clearTimeout(timer);reject(error);});child.on('close',code=>{clearTimeout(timer);try{
      const r=JSON.parse(Buffer.concat(out).toString()) as {ok:boolean;result?:unknown;code?:string};
      if(code!==0||!r.ok)throw Object.assign(new Error('Local file operation failed'),{code:r.code??'UNSAFE'});resolve(r.result);
    }catch(error){reject(error);}});child.stdin.on('error',()=>{});child.stdin.end(JSON.stringify({root:this.root,dev:this.dev,ino:this.ino,op,args}));
  });}
  async hash(path:string){return await this.call('hash',{path:this.path(path)}) as string|null;}
  async mkdir(path:string){await this.call('mkdir',{path:this.path(path)});}
  async read(path:string){return await this.call('read',{path:this.path(path)}) as string;}
  async json(path:string,text:string){await this.call('json',{path:this.path(path),text});}
  async write(path:string,bytes:string){await this.call('write',{path:this.path(path),bytes});}
  async capture(source:string,destination:string){await this.call('capture',{source:this.path(source),destination:this.path(destination)});}
  async link(source:string,destination:string){await this.call('link',{source:this.path(source),destination:this.path(destination)});}
  async copy(source:string,destination:string){await this.call('copy',{source:this.path(source),destination:this.path(destination)});}
}
