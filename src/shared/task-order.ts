/** Apply saved presentation order without dropping new or previously unlisted tasks. */
export function orderedTaskIds(ids: readonly string[], saved: unknown): string[] {
  const available = new Set(ids), seen = new Set<string>(), result: string[] = [];
  for (const id of [...(Array.isArray(saved) ? saved : []), ...ids]) {
    if (typeof id !== 'string' || !available.has(id) || seen.has(id)) continue;
    seen.add(id); result.push(id);
  }
  return result;
}

/** Reordering a filtered group replaces only its slots in the shared order. */
export function moveTaskInOrder(order: readonly string[], visible: readonly string[], id: string, target: string, placement: 'before' | 'after'): string[] {
  const included = new Set(visible), group = order.filter(value => included.has(value));
  if (id === target || !group.includes(id) || !group.includes(target)) return [...order];
  const next = group.filter(value => value !== id), index = next.indexOf(target);
  next.splice(index + (placement === 'after' ? 1 : 0), 0, id);
  let cursor = 0;
  return order.map(value => included.has(value) ? next[cursor++]! : value);
}
