import { useEffect, useId, useLayoutEffect, useRef, useState, type PointerEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { ArrowDown, ArrowUp, GripVertical } from 'lucide-react';
import { orderedTaskIds, moveTaskInOrder } from '../../src/shared/task-order';
import type { PlanningPrivateContent } from '../../src/client/planning-crypto.js';
import { content, taskName, usePlanningAction, type Project } from './shared';
import './task-order.css';

export type TaskOrderControl = {
  order: string[];
  busy: boolean;
  move: (visible: string[], id: string, target: string, placement: 'before' | 'after') => void;
};

export function useTaskOrder(project: Project) {
  const action = usePlanningAction(project), [optimistic, setOptimistic] = useState<string[] | null>(null), pending = useRef(false);
  const saved = orderedTaskIds(project.graph.tasks.map(task => task.id), content(project, project.graph.project.id).taskOrder);
  useEffect(() => { setOptimistic(null); }, [project.pin.head]);
  const order = optimistic ?? saved;
  async function move(visible: string[], id: string, target: string, placement: 'before' | 'after') {
    if (pending.current || action.busy) return;
    const next = moveTaskInOrder(order, visible, id, target, placement);
    if (next.every((value, index) => value === order[index])) return;
    pending.current = true; setOptimistic(next);
    try {
      const complete = await action.execute({ action: 'edit_project', patch: {} }, 'Task order saved', {
        content: { ...content(project, project.graph.project.id), taskOrder: next } as PlanningPrivateContent,
      });
      if (!complete) setOptimistic(null);
    } finally { pending.current = false; }
  }
  return { order, busy: action.busy, move: (visible: string[], id: string, target: string, placement: 'before' | 'after') => { void move(visible, id, target, placement); }, feedback: action.feedback };
}

type Drag = { id: string; pointerId: number; handle: HTMLButtonElement; startX: number; startY: number; x: number; y: number; active: boolean };
type Position = { id: string; placement: 'before' | 'after' };

export function ReorderableTasks<T extends { id: string }>({ tasks, project, control, children }: {
  tasks: readonly T[]; project: Project; control: TaskOrderControl; children: (task: T) => ReactNode;
}) {
  const list = useRef<HTMLDivElement>(null), drag = useRef<Drag | null>(null), suppressClick = useRef(false), instructions = useId();
  const restoreFocus = useRef<string | null>(null);
  const previousPositions = useRef(new Map<string, number>());
  const [preview, setPreview] = useState<{ id: string; x: number; y: number } | null>(null);
  const [position, setPosition] = useState<Position | null>(null), [menu, setMenu] = useState<string | null>(null);
  const positionRef = useRef<Position | null>(null);
  const ids = tasks.map(task => task.id), idsKey = ids.join('|');
  useLayoutEffect(() => {
    const next = new Map<string, number>(), reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
    for (const row of list.current?.querySelectorAll<HTMLElement>('[data-order-task]') ?? []) {
      const id = row.dataset.orderTask!, top = row.offsetTop, previous = previousPositions.current.get(id);
      next.set(id, top);
      if (!reduced && previous !== undefined && previous !== top) row.animate([{ transform: `translateY(${previous - top}px)` }, { transform: 'none' }], { duration: 180, easing: 'cubic-bezier(.2,.8,.2,1)' });
    }
    previousPositions.current = next;
  }, [idsKey]);

  function locate(y: number, id: string) {
    const candidates = Array.from(list.current?.querySelectorAll<HTMLElement>('[data-order-task]') ?? []).filter(row => row.dataset.orderTask !== id);
    let next: Position | null = null;
    for (const row of candidates) {
      const box = row.getBoundingClientRect();
      if (y < box.top + box.height / 2) { next = { id: row.dataset.orderTask!, placement: 'before' }; break; }
    }
    if (!next && candidates.length) next = { id: candidates.at(-1)!.dataset.orderTask!, placement: 'after' };
    positionRef.current = next;
    setPosition(current => current?.id === next?.id && current?.placement === next?.placement ? current : next);
  }
  function cancel() {
    const current = drag.current; drag.current = null; positionRef.current = null;
    if (current?.handle.hasPointerCapture(current.pointerId)) current.handle.releasePointerCapture(current.pointerId);
    setPreview(null); setPosition(null);
  }
  useEffect(() => { cancel(); setMenu(null); }, [idsKey, control.busy]);
  useEffect(() => {
    if (control.busy || !restoreFocus.current) return;
    const id = restoreFocus.current; restoreFocus.current = null;
    const row = Array.from(list.current?.querySelectorAll<HTMLElement>('[data-order-task]') ?? []).find(element => element.dataset.orderTask === id);
    const handle = row?.querySelector<HTMLButtonElement>('.task-drag-handle');
    // Moving a keyed row or removing its move controls can unset browser focus.
    // Restore that position unless another control has been deliberately focused.
    if (document.activeElement === document.body || document.activeElement === handle) handle?.focus();
  }, [control.busy, idsKey]);
  useEffect(() => {
    const blur = () => cancel();
    window.addEventListener('blur', blur);
    return () => { window.removeEventListener('blur', blur); const current = drag.current; if (current?.handle.hasPointerCapture(current.pointerId)) current.handle.releasePointerCapture(current.pointerId); };
  }, []);
  useEffect(() => {
    if (!preview) return;
    let frame = 0, previous = performance.now();
    const tick = (now: number) => {
      const current = drag.current;
      if (!current?.active) return;
      const elapsed = Math.min(32, now - previous); previous = now;
      const speed = current.y < 100 ? -Math.min(1, (100 - current.y) / 70) : current.y > innerHeight - 90 ? Math.min(1, (current.y - innerHeight + 90) / 70) : 0;
      if (speed) { window.scrollBy(0, speed * elapsed * .65); locate(current.y, current.id); }
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [Boolean(preview)]);

  function start(event: PointerEvent<HTMLButtonElement>, id: string) {
    if (control.busy || !event.isPrimary || event.button !== 0) return;
    // Keep the list still under the pointer; native focus can scroll WebKit
    // even when this handle is already visible.
    event.preventDefault(); event.currentTarget.focus({ preventScroll: true });
    event.currentTarget.setPointerCapture(event.pointerId); suppressClick.current = false;
    drag.current = { id, pointerId: event.pointerId, handle: event.currentTarget, startX: event.clientX, startY: event.clientY, x: event.clientX, y: event.clientY, active: false };
  }
  function move(event: PointerEvent<HTMLButtonElement>) {
    const current = drag.current;
    if (!current || event.pointerId !== current.pointerId) return;
    current.x = event.clientX; current.y = event.clientY;
    if (!current.active && Math.hypot(current.x - current.startX, current.y - current.startY) < 5) return;
    event.preventDefault(); current.active = true; suppressClick.current = true; setMenu(null);
    setPreview({ id: current.id, x: current.x, y: current.y }); locate(current.y, current.id);
  }
  function finish(event: PointerEvent<HTMLButtonElement>) {
    const current = drag.current, destination = positionRef.current;
    if (!current || current.pointerId !== event.pointerId) return;
    const bounds = list.current?.getBoundingClientRect();
    const inside = bounds && event.clientX >= bounds.left - 60 && event.clientX <= bounds.right + 60 && event.clientY >= bounds.top - 60 && event.clientY <= bounds.bottom + 60;
    cancel();
    if (current.active && destination && inside) { restoreFocus.current = current.id; control.move(ids, current.id, destination.id, destination.placement); }
  }
  function nudge(id: string, delta: number) {
    if (control.busy) return;
    const index = ids.indexOf(id), target = ids[index + delta];
    if (target) {
      const row = Array.from(list.current?.querySelectorAll<HTMLElement>('[data-order-task]') ?? []).find(element => element.dataset.orderTask === id);
      row?.querySelector<HTMLButtonElement>('.task-drag-handle')?.focus({ preventScroll: true });
      restoreFocus.current = id; setMenu(null); control.move(ids, id, target, delta < 0 ? 'before' : 'after');
    }
  }
  return <div ref={list} className="task-list task-order-list" role="list" aria-busy={control.busy}>
    <p className="sr-only" id={instructions}>Drag to reorder within this group. Use the up and down arrow keys on a handle, or open it for move controls.</p>
    {tasks.map((task, index) => <div role="listitem" key={task.id} data-order-task={task.id}
      className={`task-order-row${preview?.id === task.id ? ' is-dragging' : ''}${position?.id === task.id ? ` insert-${position.placement}` : ''}`}>
      <button type="button" className="task-drag-handle" aria-disabled={control.busy} aria-label={`Reorder ${taskName(project, task.id)}`} aria-describedby={instructions}
        aria-expanded={menu === task.id} title="Drag to reorder · Arrow keys to move" onPointerDown={event => start(event, task.id)} onPointerMove={move}
        onPointerUp={finish} onPointerCancel={cancel} onLostPointerCapture={() => { if (drag.current) cancel(); }}
        onClick={event => { if (control.busy) return; const suppress = suppressClick.current && event.detail > 0; suppressClick.current = false; if (!suppress) setMenu(current => current === task.id ? null : task.id); }}
        onKeyDown={event => { if (event.key === 'ArrowUp' || event.key === 'ArrowDown') { event.preventDefault(); nudge(task.id, event.key === 'ArrowUp' ? -1 : 1); } else if (event.key === 'Escape') { event.preventDefault(); cancel(); setMenu(null); } }}><GripVertical size={17}/></button>
      {children(task)}
      {menu === task.id && <div className="task-order-actions" aria-label={`Move ${taskName(project, task.id)}`}>
        <button type="button" disabled={index === 0 || control.busy} onClick={() => nudge(task.id, -1)}><ArrowUp size={14}/>Move up</button>
        <button type="button" disabled={index === tasks.length - 1 || control.busy} onClick={() => nudge(task.id, 1)}><ArrowDown size={14}/>Move down</button>
      </div>}
    </div>)}
    {preview && createPortal(<div className="task-drag-preview" style={{ left: Math.max(12, Math.min(preview.x + 14, window.innerWidth - 292)), top: Math.max(12, Math.min(preview.y + 12, window.innerHeight - 80)) }}><GripVertical size={16}/><span>{taskName(project, preview.id)}</span></div>, document.body)}
    <span className="sr-only" role="status">{control.busy ? 'Saving task order' : preview ? `Moving ${taskName(project, preview.id)}` : ''}</span>
  </div>;
}
