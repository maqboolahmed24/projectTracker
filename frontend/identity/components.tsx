import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { ArrowLeft, ArrowRight, Check, Copy, Download, Eye, EyeOff, KeyRound, ShieldCheck } from 'lucide-react';
import type { ClientRuntime } from '../../src/client/runtime.js';
import type { AvatarSelection } from '../../src/shared/avatar.js';
import { Avatar, Button, Field, Input } from '../shared/ui.js';
import { getClientLibrary } from '../shared/runtime.js';
import { downloadPrivateFile } from './handoff.js';

export function identityError(error: unknown): string {
  const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
  const messages: Record<string, string> = {
    AUTHENTICATION: 'That password didn’t work. Please try again.', PROOF_REQUIRED: 'Please check your password and try again.',
    AUTH_REQUIRED: 'Please sign in again to continue.', REAUTH_REQUIRED: 'Please confirm your password to continue.',
    PASSWORD_CONFIRMATION: 'Your passwords don’t match.', PASSWORD_POLICY: 'Use a less common password with at least 15 characters.',
    PASSWORD_TOO_WEAK: 'Use a less common password with at least 15 characters.',
    RATE_LIMITED: 'Too many attempts. Please wait a little before trying again.',
    TRANSPORT: 'We couldn’t connect. Check your connection and try again.', UNAVAILABLE: 'This is temporarily unavailable. Please try again.',
    OFFLINE: 'You’re offline. Reconnect to continue.',
    CONFLICT: 'Something changed while you were here. Check the latest progress, then try again.',
    EXPIRED: 'This request has expired. Ask an Owner for a new invitation or temporary key.',
    FORBIDDEN: 'You don’t have access to this action. Please ask an Owner for help.',
    STORAGE: 'This browser couldn’t save your secure sign-in. Allow site storage, then try again.',
    LOCAL_DEVICE_UNAVAILABLE: 'This device needs approval before you can continue.',
    INCOMPLETE_KEYS: 'Your access is still being prepared. Check again in a moment.',
    TRUST_REQUIRED: 'We couldn’t verify this request. Check the private link with the person who sent it.',
    FINGERPRINT_MISMATCH: 'The security checks don’t match. Compare the complete check with the other person before continuing.',
    INVALID_PROFILE: 'We couldn’t verify your profile. Please sign in again.',
    CANCELLED: 'This action was stopped. You can continue when you’re ready.',
    LOCAL_CLEANUP: 'You’re locked out on this device. Please retry signing out to finish securely.',
    NOT_FOUND: 'This saved request is no longer available. Use a current private link or ask an Owner for help.',
  };
  if (messages[code]) return messages[code];
  if (['INVALID_PAIRING', 'INVALID_RECOVERY', 'INVALID_ENROLMENT', 'INVALID_DRAFT', 'INVALID_CONTEXT', 'RECEIPT_MISMATCH', 'LOCAL_VERIFICATION', 'CONTEXT_MISMATCH'].includes(code)) return 'We couldn’t verify this request safely. Nothing further has been approved. Ask an Owner to check it with you.';
  if (error instanceof Error && (error.message.startsWith('This link ') || error.message.startsWith('Please ') || error.message.startsWith('Your ') || error.message.startsWith('Use ') || error.message.startsWith('Recovery words '))) return error.message;
  return 'We couldn’t complete that step. Check your details and try again.';
}
export function useIdentityAction() {
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const alive = useRef(true), running = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const run = async (action: () => Promise<unknown>) => {
    if (running.current) return; running.current = true; if (alive.current) { setBusy(true); setError(''); }
    try { await action(); } catch (e) { if (alive.current) setError(identityError(e)); }
    finally { running.current = false; if (alive.current) setBusy(false); }
  };
  return { busy, error, setError, run };
}
export function Notice({ children, tone = 'info' }: { children: ReactNode; tone?: 'info' | 'error' | 'success' }) {
  return <div className={`notice identity-notice ${tone}`} role={tone === 'error' ? 'alert' : 'status'}>{children}</div>;
}
export function IdentityFrame({ title, description, eyebrow = 'YOUR SPACE TO DO GREAT WORK', children, onBack, busy = false }: { title: string; description: string; eyebrow?: string; children: ReactNode; onBack?: () => void; busy?: boolean }) {
  return <div className="auth-layout">
    <aside className="auth-aside"><div className="identity-brand"><img src="/brand/assets/ukds-symbol.svg" alt="" width={42} height={48}/><span>Maqbool</span></div><div className="identity-orbit" aria-hidden="true"><div className="identity-orbit-inner"><ShieldCheck size={44} strokeWidth={1.25}/></div></div><p className="eyebrow">A little clarity. A lot of possibility.</p><h2>Bring your next<br/>big thing to life.</h2><p>One calm place for your people, your plans, and everything you’re building together.</p><div className="identity-aside-caption"><span className="identity-aside-dot"/>Private by design. Made for working together.</div></aside>
    <main className="auth-panel"><div className="auth-card">
      {onBack && <Button variant="ghost" onClick={onBack} disabled={busy} className="identity-back"><ArrowLeft size={16}/>Back</Button>}
      <header><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="muted">{description}</p></header>
      {children}
    </div></main>
  </div>;
}
export function PasswordField({ value, onChange, label = 'Password', newPassword = false, required = true }: { value: string; onChange: (value: string) => void; label?: string; newPassword?: boolean; required?: boolean }) {
  const [visible, setVisible] = useState(false), id = useId();
  return <Field label={label} hint={newPassword ? 'At least 15 characters. A few memorable words work well.' : undefined}><div className="identity-password"><Input id={id} type={visible ? 'text' : 'password'} value={value} onChange={e => onChange(e.target.value)} autoComplete={newPassword ? 'new-password' : 'current-password'} required={required} maxLength={2048}/><button type="button" className="identity-password-toggle" onClick={() => setVisible(v => !v)} aria-label={visible ? 'Hide password' : 'Show password'}>{visible ? <EyeOff size={18}/> : <Eye size={18}/>}</button></div></Field>;
}
export function ShareLink({ link, title = 'Share this private link', description = 'Send it directly to the right person. It only works for this request.' }: { link: string; title?: string; description?: string }) {
  const [copied, setCopied] = useState(false), [error, setError] = useState('');
  useEffect(() => { setCopied(false); setError(''); }, [link]);
  return <section className="identity-share"><h3>{title}</h3><p className="muted">{description}</p><div className="button-row"><Button variant="secondary" onClick={async () => { try { await navigator.clipboard.writeText(link); setCopied(true); } catch { setError('Copy is unavailable. Save the link file instead.'); } }}>{copied ? <Check size={16}/> : <Copy size={16}/>} {copied ? 'Copied' : 'Copy private link'}</Button><Button variant="ghost" onClick={() => downloadPrivateFile('workspace-private-link.json', JSON.parse(atob(link.split('#access=')[1]!.replaceAll('-', '+').replaceAll('_', '/'))))}><Download size={16}/>Save link</Button></div>{error && <Notice tone="error">{error}</Notice>}</section>;
}
export function DeviceSecurityCode({ fingerprint }: { fingerprint: string }) {
  return <output className="identity-fingerprint identity-device-code" aria-label="Your complete security check">
    {fingerprint.match(/.{1,8}/g)?.map((group, index) => <span key={index}>{group}{index < 7 ? ' ' : ''}</span>)}
  </output>;
}

export function DeviceSecurityComparison({ fingerprint, onConfirm, busy = false }: { fingerprint: string; onConfirm: (confirmed: string) => void; busy?: boolean }) {
  // A mismatch belongs to the code that was compared, never to a later request.
  const [mismatchedCode, setMismatchedCode] = useState<string | null>(null);
  useEffect(() => { setMismatchedCode(null); }, [fingerprint]);
  const mismatch = mismatchedCode === fingerprint;
  const valid = /^[0-9a-f]{64}$/.test(fingerprint);
  return <section className="form-stack identity-comparison" aria-busy={busy}>
    <div className="identity-icon"><ShieldCheck size={24}/></div>
    <h2>Compare both screens</h2>
    <p className="muted">Compare all eight groups below with the code shown on the other device. Every character must match. If an Owner is helping, compare the codes together in person or on a call you trust.</p>
    <DeviceSecurityCode fingerprint={fingerprint}/>
    {!valid ? <Notice tone="error">The code isn’t ready. Check this request again before continuing.</Notice> : mismatch ? <>
      <Notice tone="error">Don’t approve this request while the codes differ. Make sure both screens show the same request, then compare again.</Notice>
      <Button variant="secondary" disabled={busy} onClick={() => setMismatchedCode(null)}>Compare again</Button>
    </> : <>
      <Button disabled={busy} busy={busy} onClick={() => { if (!busy) onConfirm(fingerprint); }}>The codes match<ArrowRight size={16}/></Button>
      <Button variant="ghost" disabled={busy} onClick={() => setMismatchedCode(fingerprint)}>The codes don’t match</Button>
    </>}
  </section>;
}

export function SecurityComparison({ fingerprint, onConfirm, busy, phrase = false }: { fingerprint: string; onConfirm: (confirmed: string) => void; busy?: boolean; phrase?: boolean }) {
  const [partner, setPartner] = useState(''), [ack, setAck] = useState(false);
  useEffect(() => { setPartner(''); setAck(false); }, [fingerprint]);
  const cleaned = partner.toLowerCase().replace(/\s|-/g, '');
  const match = cleaned === fingerprint;
  return <section className="form-stack identity-comparison"><div className="identity-icon"><ShieldCheck size={24}/></div><h2>One quick security check</h2><p className="muted">{phrase ? 'Your saved recovery kit has verified this workspace. Confirm that you want this device to replace your previous access.' : 'Compare the complete check below with the other person in person, on a call, or through a private channel you trust.'}</p><output className="identity-fingerprint" aria-label="Your complete security check">{fingerprint.match(/.{1,8}/g)?.join(' ')}</output>{phrase ? <label className="identity-check"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I’m recovering my account on this device.</label> : <Field label="The check from the other person" hint="Paste all eight groups. They must match exactly."><Input value={partner} onChange={e => setPartner(e.target.value)} autoComplete="off" spellCheck={false}/></Field>}{!phrase && partner && !match && <p className="identity-inline-error">The checks don’t match yet.</p>}<Button disabled={busy || !(phrase ? ack : match)} busy={!!busy} onClick={() => onConfirm(phrase ? fingerprint : cleaned)}>Confirm and continue<ArrowRight size={16}/></Button></section>;
}
export interface PersonalSetupValue { displayName: string; workspaceName: string; password: string; confirmation: string; avatar: AvatarSelection; ownerKit?: { phrase: string; positions: number[]; answers: string[] } }
export function PersonalSetup({ client, owner, workspace = false, promotion = false, recoveryMode = false, retained = false, busy, onSubmit }: { client: ClientRuntime; owner: boolean; workspace?: boolean; promotion?: boolean; recoveryMode?: boolean; retained?: boolean; busy: boolean; onSubmit: (value: PersonalSetupValue) => Promise<void> }) {
  const [name, setName] = useState(''), [workspaceName, setWorkspaceName] = useState(''), [password, setPassword] = useState(''), [confirmation, setConfirmation] = useState('');
  const [avatar, setAvatar] = useState<AvatarSelection>({shapeId:'shape-01', colourId:'teal'});
  const [phrase, setPhrase] = useState(''), [positions, setPositions] = useState<number[]>([]), [answers, setAnswers] = useState<string[]>(['','','']);
  const [saved, setSaved] = useState(false), [step, setStep] = useState<'details' | 'words' | 'confirm'>('details'), action = useIdentityAction();
  const [palette, setPalette] = useState<{id:string;label:string;hex:string}[]>([]);
  useEffect(() => { let active = true; void getClientLibrary().then(l => { if (active) setPalette([...l.avatarColours]); }); return () => { active = false; }; }, []);
  useEffect(() => client.auth.onClear(() => { setPassword(''); setConfirmation(''); setPhrase(''); setAnswers(['','','']); }), [client]);
  const next = () => action.run(async () => {
    const lib = await getClientLibrary();
    if (!promotion && !retained) { lib.password.validateNewPassword(password); if (password !== confirmation) throw new Error('Your passwords don’t match.'); }
    if ((!promotion && !recoveryMode && !retained && !name.trim()) || (workspace && !workspaceName.trim())) throw new Error('Please enter the names before continuing.');
    if (owner) { if (retained) { if (phrase.trim().split(/\s+/).length !== 24) throw new Error('Please enter the recovery words you saved for this setup.'); setPhrase(phrase.trim().toLowerCase().split(/\s+/).join(' ')); setPositions(await lib.recovery.recoveryChallenge()); } else if (!phrase) { setPhrase(await lib.recovery.newOwnerPhrase()); setPositions(await lib.recovery.recoveryChallenge()); } setStep('words'); }
    else await onSubmit({displayName:name.trim(), workspaceName:workspaceName.trim(), password, confirmation:retained?password:confirmation, avatar});
  });
  const submit = () => action.run(async () => {
    (await getClientLibrary()).recovery.verifyRecoveryWords(phrase, positions, answers);
    await onSubmit({displayName:name.trim(), workspaceName:workspaceName.trim(), password, confirmation:promotion||retained ? password : confirmation, avatar, ownerKit:{phrase,positions,answers}});
  });
  return <div className="form-stack">{owner && <ol className="stepper" aria-label="Setup progress"><li aria-current={step==='details'?'step':undefined}>Your details</li><li aria-current={step==='words'?'step':undefined}>Recovery words</li><li aria-current={step==='confirm'?'step':undefined}>Confirm backup</li></ol>}
    {step === 'details' && <form className="form-stack" onSubmit={e => {e.preventDefault();void next();}}>
      {!promotion && !recoveryMode && !retained && <><Field label="Your name"><Input value={name} onChange={e=>setName(e.target.value)} autoComplete="name" required maxLength={200} autoFocus/></Field>{workspace && <Field label="Workspace name"><Input value={workspaceName} onChange={e=>setWorkspaceName(e.target.value)} required maxLength={200} placeholder="Your team or organisation"/></Field>}
      <fieldset className="identity-avatar-picker"><legend>Make it yours</legend><div className="identity-avatar-preview"><Avatar selection={avatar} name={name} size={76}/><p className="muted">Choose a character and a colour.</p></div><div className="identity-avatar-grid">{Array.from({length:20},(_,i)=>`shape-${String(i+1).padStart(2,'0')}`).map((shape,i)=><button className={avatar.shapeId===shape?'selected':''} type="button" key={shape} aria-label={`Character ${i+1}`} aria-pressed={avatar.shapeId===shape} onClick={()=>setAvatar({...avatar,shapeId:shape as AvatarSelection['shapeId']})}><Avatar selection={{...avatar,shapeId:shape as AvatarSelection['shapeId']}} size={40} name={`Character ${i+1}`}/></button>)}</div><div className="identity-colours">{palette.map(colour=><button key={colour.id} type="button" style={{backgroundColor:colour.hex}} aria-label={colour.label} aria-pressed={avatar.colourId===colour.id} className={avatar.colourId===colour.id?'selected':''} onClick={()=>setAvatar({...avatar,colourId:colour.id as AvatarSelection['colourId']})}>{avatar.colourId===colour.id && <Check size={16}/>}</button>)}</div></fieldset></>}
      {retained && <Notice>Your name, character and password are already saved. Confirm your password to continue with the current Owner.</Notice>}{retained && owner && <Field label="The 24 recovery words saved for this setup"><Input value={phrase} onChange={e=>setPhrase(e.target.value)} required autoComplete="off" spellCheck={false}/></Field>}
      <PasswordField value={password} onChange={setPassword} newPassword={!promotion&&!retained} label={promotion||retained?'Current password':'Create a password'}/>{!promotion&&!retained && <PasswordField value={confirmation} onChange={setConfirmation} newPassword label="Confirm password"/>}<Button busy={busy||action.busy} type="submit">Continue<ArrowRight size={16}/></Button>
    </form>}
    {step === 'words' && <><div className="identity-icon"><KeyRound size={24}/></div><h2>Your personal recovery words</h2><p className="muted">These 24 words let you recover your Owner account. Keep them somewhere private, outside this browser. Each Owner has their own words.</p><ol className="identity-recovery-words">{phrase.split(' ').map((word,i)=><li key={i}><span>{i+1}</span>{word}</li>)}</ol><label className="identity-check"><input type="checkbox" checked={saved} onChange={e=>setSaved(e.target.checked)}/>I’ve written these words down somewhere safe.</label><div className="button-row"><Button variant="ghost" onClick={()=>setStep('details')}>Back</Button><Button disabled={!saved} onClick={()=>setStep('confirm')}>Check my backup<ArrowRight size={16}/></Button></div></>}
    {step === 'confirm' && <form className="form-stack" onSubmit={e=>{e.preventDefault();void submit();}}><h2>Let’s check your backup</h2><p className="muted">Look at your saved words and enter the three requested below.</p>{positions.map((position,i)=><Field key={position} label={`Word ${position+1}`}><Input value={answers[i]??''} onChange={e=>setAnswers(a=>a.map((v,j)=>j===i?e.target.value:v))} required autoComplete="off" autoCorrect="off" spellCheck={false}/></Field>)}<div className="button-row"><Button variant="ghost" onClick={()=>setStep('words')}>View words again</Button><Button type="submit" busy={busy||action.busy}>Confirm backup<ArrowRight size={16}/></Button></div></form>}
    {action.error && <Notice tone="error">{action.error}</Notice>}
  </div>;
}
