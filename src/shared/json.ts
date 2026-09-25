/** Bounded JSON reader that rejects duplicate keys instead of silently changing signed data. */
export function parseJsonStrict(source: string): unknown {
  let offset = 0;
  const fail = (): never => { throw new SyntaxError('Invalid JSON'); };
  const whitespace = () => { while (/[\x20\t\r\n]/.test(source[offset] ?? 'x')) offset++; };
  const string = (): string => {
    const start = offset++;
    while (offset < source.length) {
      const char = source[offset++];
      if (char === '\\') { offset++; continue; }
      if (char === '"') {
        const value: unknown = JSON.parse(source.slice(start, offset));
        if (typeof value !== 'string' || /[\uD800-\uDFFF]/u.test(value)) fail();
        return value as string;
      }
    }
    return fail();
  };
  const value = (depth: number): unknown => {
    if (depth > 64) fail();
    whitespace();
    const char = source[offset];
    if (char === '"') return string();
    if (char === '{') {
      offset++;
      const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const keys = new Set<string>();
      whitespace();
      if (source[offset] === '}') { offset++; return result; }
      while (offset < source.length) {
        whitespace();
        if (source[offset] !== '"') fail();
        const key = string();
        if (keys.has(key) || key === '__proto__' || key === 'constructor') fail();
        keys.add(key);
        whitespace();
        if (source[offset++] !== ':') fail();
        result[key] = value(depth + 1);
        whitespace();
        if (source[offset] === '}') { offset++; return result; }
        if (source[offset++] !== ',') fail();
      }
      return fail();
    }
    if (char === '[') {
      offset++;
      const result: unknown[] = [];
      whitespace();
      if (source[offset] === ']') { offset++; return result; }
      while (offset < source.length) {
        result.push(value(depth + 1));
        whitespace();
        if (source[offset] === ']') { offset++; return result; }
        if (source[offset++] !== ',') fail();
      }
      return fail();
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(source.slice(offset))?.[0];
    if (!token) return fail();
    offset += token.length;
    const result: unknown = JSON.parse(token);
    if (typeof result === 'number' && !Number.isFinite(result)) fail();
    return result;
  };
  const result = value(0);
  whitespace();
  if (offset !== source.length) fail();
  return result;
}
