import { expect, test } from '@playwright/test';

for (const capability of ['WebAssembly', 'crypto', 'indexedDB'] as const) {
  test(`CP13: missing Worker ${capability} rejects client startup before any authentication request`, async ({ page }) => {
    const apiRequests: string[] = [];
    page.on('request', request => { if (new URL(request.url()).pathname.startsWith('/v1/')) apiRequests.push(request.url()); });
    let intercepted = false;
    await page.route('**/chunk-*.js', async route => {
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      const body = await response.text();
      const property = capability === 'WebAssembly' ? 'webAssembly' : capability;
      const capture = `${property}: globalThis.${capability}`;
      // The bundled shared module installs the handler during static import.
      // Omit the capability from its real environment at that capture point;
      // preserve static loading so the first Worker message is never lost.
      if (body.includes('installAuthWorker(globalThis, {') && body.includes(capture)) {
        intercepted = true;
        await route.fulfill({ response, body: body.replace(capture, `${property}: undefined`) });
      } else await route.fulfill({ response });
    });
    await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
    const result = await page.evaluate(async () => {
      try { const client = await window.ukda.openClient(); await client.close(); return 'unexpected success'; }
      catch (error) { return (error as { code?: string }).code ?? 'unclassified failure'; }
    });
    expect(intercepted).toBe(true); expect(result).toBe('UNSUPPORTED'); expect(apiRequests).toEqual([]);
  });
}
