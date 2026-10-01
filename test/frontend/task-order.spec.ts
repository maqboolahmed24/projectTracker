import { expect, test, type Locator, type Page } from '@playwright/test';
import { authenticationFixture } from '../browser/authentication-fixture.js';
import { navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

async function titles(group: Locator) { return group.locator('.task-title').allTextContents(); }
async function drag(page: Page, handle: Locator, target: Locator, after: boolean) {
  await handle.scrollIntoViewIfNeeded();
  const from = await handle.boundingBox(), to = await target.boundingBox();
  if (!from || !to) throw new Error('Task drag controls are unavailable');
  await page.mouse.move(from.x + from.width / 2, from.y + from.height / 2);
  const scrollBefore = await page.evaluate(() => scrollY);
  await page.mouse.down();
  expect(await page.evaluate(() => scrollY)).toBe(scrollBefore);
  await page.mouse.move(from.x + from.width / 2, to.y + (after ? to.height - 7 : 7), { steps: 12 });
  await expect(page.locator('.task-drag-preview')).toBeVisible();
  await expect(page.locator(after ? '.insert-after' : '.insert-before')).toHaveCount(1);
  await page.mouse.up();
}

test('task order saves pointer, keyboard and touch moves, preserves groups, and recovers failed or uncertain writes', async ({ page }, testInfo) => {
  test.setTimeout(240_000);
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  let stage = 'create project and tasks';
  const transportEvents: unknown[] = [], windowErrors: unknown[] = [];
  const accessRefreshPaths = new Set(['/v1/auth/access-change/delivery', '/v1/auth/access-change/delivery/history']);
  const pageErrors: { stage: string; message: string; stack: string }[] = [], cancelledDelivery = new Set<string>(), rejectedDelivery = new Set<string>();
  page.on('pageerror', error => {
    const entry = { stage, event: 'pageerror', message: error.message,
      stack: error.stack?.replace(/https?:\/\/[^\s)]+/g, value => { try { return new URL(value).pathname; } catch { return '[URL]'; } }) ?? '' };
    pageErrors.push(entry); transportEvents.push(entry);
  });
  page.on('requestfailed', request => {
    const path = new URL(request.url()).pathname, reason = request.failure()?.errorText;
    transportEvents.push({ stage, event: 'requestfailed', path, reason });
    if (accessRefreshPaths.has(path) && reason === 'cancelled') cancelledDelivery.add(stage);
  });
  page.on('response', response => {
    const path = new URL(response.url()).pathname;
    if (response.status() >= 400 && (accessRefreshPaths.has(path) || path === '/v1/work/planning/save')) {
      transportEvents.push({ stage, event: 'response', path, status: response.status() });
      if (accessRefreshPaths.has(path)) rejectedDelivery.add(stage);
    }
  });
  await page.exposeFunction('recordTaskOrderWindowError', (details: unknown) => { windowErrors.push(details); transportEvents.push({ stage, details }); });
  await page.addInitScript(() => {
    const report = (window as Window & { recordTaskOrderWindowError?: (details: unknown) => Promise<void> }).recordTaskOrderWindowError;
    window.addEventListener('error', event => { void report?.({ event: 'window.error', path: event.filename ? new URL(event.filename, location.href).pathname : '', line: event.lineno, column: event.colno })?.catch(() => {}); });
    window.addEventListener('unhandledrejection', event => { void report?.({ event: 'window.unhandledrejection', name: event.reason instanceof Error ? event.reason.name : typeof event.reason })?.catch(() => {}); });
  });
  const name = 'A shared order for the next steps', phaseName = 'Prepare the release';
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await seedRememberedOwner(page, fixture); await signIn(page);
    await page.getByRole('button', { name: 'New project', exact: true }).click();
    let dialog = page.getByRole('dialog', { name: 'A fresh start', exact: true });
    await dialog.getByLabel('Project name', { exact: true }).fill(name);
    await dialog.getByRole('button', { name: 'Create project', exact: true }).click();
    await expect.poll(async () => {
      const check = dialog.getByRole('button', { name: 'Check progress', exact: true });
      if (await check.isVisible() && await check.isEnabled()) await check.click();
      return page.getByRole('heading', { name, exact: true, level: 1 }).isVisible();
    }).toBe(true);
    const projectId = new URL(page.url()).pathname.split('/')[2]!;
    await navigate(page, `/projects/${projectId}/work`);
    await page.getByRole('button', { name: 'Add phase', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Add phase', exact: true });
    await dialog.getByLabel('Name', { exact: true }).fill(phaseName);
    await dialog.getByRole('button', { name: 'Add phase', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    for (const title of ['Queue — write the outline', 'Review the evidence', 'Queue — check the examples', 'Separate project task']) {
      await page.locator('.page-header').getByRole('button', { name: 'Add task', exact: true }).click();
      dialog = page.getByRole('dialog', { name: 'Add a task', exact: true });
      await dialog.getByLabel('Task name', { exact: true }).fill(title);
      if (title !== 'Separate project task') await dialog.getByLabel('Phase', { exact: true }).selectOption({ label: phaseName });
      await dialog.getByRole('button', { name: 'Add task', exact: true }).click();
      await expect(dialog).toHaveCount(0);
    }
    const group = page.locator('.task-group').filter({ has: page.getByRole('button', { name: phaseName, exact: true }) });
    const other = page.locator('.task-group').filter({ hasText: 'Unscheduled work' });
    const handle = (title: string) => group.getByRole('button', { name: `Reorder ${title}`, exact: true });
    const row = (title: string) => group.locator('[data-order-task]').filter({ has: page.locator('.task-title', { hasText: title }) });
    const settled = async () => { await expect(group.locator('.task-order-list')).toHaveAttribute('aria-busy', 'false'); await expect(group.locator('.task-drag-handle[aria-disabled=true]')).toHaveCount(0); };
    let writes = 0;
    page.on('request', request => { if (request.method() === 'POST' && request.url().endsWith('/v1/work/planning/save')) writes++; });

    const initial = await titles(group);
    expect(initial).toHaveLength(3);
    // Pointer-only diagnostics omit task text and identity information.
    await page.evaluate(() => {
      const trace: unknown[] = [], state = window as Window & { taskOrderTrace?: unknown[]; stopTaskOrderTrace?: () => void };
      const record = (event: Event) => {
        const pointer = event as PointerEvent, target = event.target instanceof Element ? event.target.closest('.task-drag-handle') : null;
        const list = target?.closest('.task-order-list') ?? document.querySelector('.task-order-list'), box = list?.getBoundingClientRect();
        trace.push({ type: event.type, x: pointer.clientX, y: pointer.clientY, buttons: pointer.buttons, pointer: pointer.pointerType,
          handle: !!target, capture: !!target?.hasPointerCapture(pointer.pointerId), scroll: scrollY,
          bounds: box ? [box.left, box.top, box.right, box.bottom] : null, busy: list?.getAttribute('aria-busy'),
          preview: !!document.querySelector('.task-drag-preview'), insertion: list?.querySelector('.insert-before,.insert-after')?.className ?? null });
      };
      const events = ['pointerdown', 'pointermove', 'pointerup', 'pointercancel', 'gotpointercapture', 'lostpointercapture', 'blur'];
      for (const event of events) window.addEventListener(event, record, true);
      state.taskOrderTrace = trace;
      state.stopTaskOrderTrace = () => { for (const event of events) window.removeEventListener(event, record, true); };
    });
    let expected = [initial[1]!, initial[2]!, initial[0]!];
    try {
      await drag(page, handle(initial[0]!), row(initial[2]!), true);
      await expect.poll(() => titles(group)).toEqual(expected); await settled();
    } catch (error) {
      const trace = await page.evaluate(() => (window as Window & { taskOrderTrace?: unknown[] }).taskOrderTrace);
      await testInfo.attach('task-order-pointer-stages', { body: JSON.stringify({ writes, trace }, null, 2), contentType: 'application/json' });
      throw error;
    } finally {
      await page.evaluate(() => (window as Window & { stopTaskOrderTrace?: () => void }).stopTaskOrderTrace?.());
    }
    await expect(page.locator('dialog[open]')).toHaveCount(0);
    expect(writes).toBe(1);
    await expect(handle(initial[0]!)).toBeFocused();
    await expect(other.locator('.task-title')).toHaveText('Separate project task');

    // Releasing outside the source group or cancelling never saves an order.
    const cancelledTask = expected[2]!, cancelledHandle = handle(cancelledTask);
    await cancelledHandle.scrollIntoViewIfNeeded();
    let grip = await cancelledHandle.boundingBox(), bounds = await group.locator('.task-order-list').boundingBox();
    if (!grip || !bounds) throw new Error('Cancellation targets are unavailable');
    await page.mouse.move(grip.x + grip.width / 2, grip.y + grip.height / 2); await page.mouse.down();
    await page.mouse.move(grip.x + grip.width / 2, bounds.y - 75, { steps: 8 });
    await expect(page.locator('.task-drag-preview')).toBeVisible(); await page.mouse.up();
    await expect(page.locator('.task-drag-preview')).toHaveCount(0);
    expect(await titles(group)).toEqual(expected); expect(writes).toBe(1);
    grip = await cancelledHandle.boundingBox();
    if (!grip) throw new Error('Cancellation handle is unavailable');
    await page.mouse.move(grip.x + grip.width / 2, grip.y + grip.height / 2); await page.mouse.down();
    await page.mouse.move(grip.x + grip.width / 2, grip.y - 30, { steps: 4 });
    await page.keyboard.press('Escape'); await page.mouse.up();
    await expect(page.locator('.task-drag-preview')).toHaveCount(0);
    await cancelledHandle.focus(); await page.keyboard.press('Enter');
    await expect(cancelledHandle).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('Escape');
    expect(await titles(group)).toEqual(expected); expect(writes).toBe(1);

    // Focus stays on the same task through repeated saves, with a separate
    // opening button and explicit move controls for people who do not drag.
    await handle(expected[1]!).focus(); await page.keyboard.press('ArrowUp');
    expected = [expected[1]!, expected[0]!, expected[2]!];
    await expect.poll(() => titles(group)).toEqual(expected); await settled();
    await expect(handle(expected[0]!)).toBeFocused();
    await page.keyboard.press('ArrowDown');
    expected = [expected[1]!, expected[0]!, expected[2]!];
    await expect.poll(() => titles(group)).toEqual(expected); await settled();
    await expect(handle(expected[1]!)).toBeFocused();
    const menuTask = expected[0]!;
    await handle(menuTask).click();
    await expect(handle(menuTask)).toHaveAttribute('aria-expanded', 'true');
    await handle(menuTask).click();
    await expect(handle(menuTask)).toHaveAttribute('aria-expanded', 'false');
    await handle(menuTask).click();
    await row(menuTask).getByRole('button', { name: 'Move down', exact: true }).click();
    expected = [expected[1]!, expected[0]!, expected[2]!];
    await expect.poll(() => titles(group)).toEqual(expected); await settled();
    await expect(handle(menuTask)).toBeFocused();

    // Filtering changes only those visible slots, not the position of hidden
    // tasks or the phase/project assignments.
    const beforeFilter = [...expected], hiddenIndex = expected.indexOf('Review the evidence');
    await page.getByLabel('Search project tasks', { exact: true }).fill('Queue');
    const visible = await titles(group);
    await handle(visible[1]!).focus(); await page.keyboard.press('ArrowUp');
    await expect.poll(() => titles(group)).toEqual([...visible].reverse()); await settled();
    await page.getByLabel('Search project tasks', { exact: true }).fill('');
    expected = await titles(group);
    expect(expected[hiddenIndex]).toBe('Review the evidence');
    expect(expected.filter(title => title.startsWith('Queue'))).toEqual(beforeFilter.filter(title => title.startsWith('Queue')).reverse());
    await expect(other.locator('.task-title')).toHaveText('Separate project task');

    // A documented workspace restriction is a definite rejection. Unknown HTTP
    // errors intentionally remain uncertain and must not unlock a second write.
    stage = 'definite workspace restriction';
    await page.route('**/v1/work/planning/save', route => route.fulfill({ status: 423, contentType: 'application/json', body: JSON.stringify({ error: { code: 'WORKSPACE_RESTRICTED', message: 'Workspace writes are temporarily restricted' } }) }), { times: 1 });
    await handle(expected[1]!).focus(); await page.keyboard.press('ArrowUp');
    await expect(page.locator('.task-order-feedback').getByRole('alert')).toBeVisible();
    await expect.poll(() => titles(group)).toEqual(expected); await settled();
    await expect(page.locator('.task-order-feedback').getByRole('button', { name: /Try again/ })).toHaveCount(0);

    // An already committed save with a lost reply locks ordering until its
    // durable operation is checked. Retrying must not write a second order.
    stage = 'lost planning save reply';
    const savesBeforeLostReply = writes;
    await page.route('**/v1/work/planning/save', async route => { const response = await route.fetch(); expect(response.status()).toBe(200); await route.abort('failed'); }, { times: 1 });
    await handle(expected[1]!).focus(); await page.keyboard.press('ArrowUp');
    await expect(page.locator('.task-order-feedback').getByRole('alert')).toBeVisible();
    await expect(group.locator('.task-drag-handle[aria-disabled=true]')).toHaveCount(3);
    await expect.poll(() => titles(group)).toEqual(expected);
    const busyHandle = handle(expected[1]!);
    await busyHandle.focus(); await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter');
    await expect(busyHandle).toBeFocused(); await expect(busyHandle).toHaveAttribute('aria-expanded', 'false');
    const busyBox = await busyHandle.boundingBox();
    if (!busyBox) throw new Error('Busy handle is unavailable');
    await page.mouse.click(busyBox.x + busyBox.width / 2, busyBox.y + busyBox.height / 2);
    await expect(busyHandle).toHaveAttribute('aria-expanded', 'false');
    await page.mouse.down(); await page.mouse.move(busyBox.x + busyBox.width / 2, busyBox.y - 30, { steps: 4 });
    await expect(page.locator('.task-drag-preview')).toHaveCount(0); await page.mouse.up();
    expect(await titles(group)).toEqual(expected); expect(writes - savesBeforeLostReply).toBe(1);
    await page.locator('.task-order-feedback').getByRole('button', { name: /Try again/ }).click();
    expected = [expected[1]!, expected[0]!, expected[2]!];
    await expect.poll(() => titles(group)).toEqual(expected); await settled();
    expect(writes - savesBeforeLostReply).toBe(1);

    await group.locator('.task-row').filter({ hasText: expected[0]! }).click();
    dialog = page.getByRole('dialog', { name: expected[0]!, exact: true });
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
    stage = 'reload after ordering';
    await page.reload(); await signIn(page);
    await navigate(page, `/projects/${projectId}/work`);
    await expect.poll(() => titles(group)).toEqual(expected);

    // Editing ordinary project details must retain its encrypted ordering field.
    stage = 'edit project details';
    await page.getByRole('button', { name: 'Project options', exact: true }).click();
    await page.getByRole('button', { name: 'Edit details', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Project details', exact: true });
    await dialog.getByLabel('Description', { exact: true }).fill('A considered order, shared with the team.');
    await dialog.getByRole('button', { name: 'Save changes', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    stage = 'reload after editing details';
    await page.reload(); await signIn(page);
    await navigate(page, `/projects/${projectId}/work`);
    await expect.poll(() => titles(group)).toEqual(expected);
    await page.setViewportSize({ width: 390, height: 844 });
    if (testInfo.project.name === 'chromium') {
      const session = await page.context().newCDPSession(page);
      await session.send('Emulation.setTouchEmulationEnabled', { enabled: true });
      await group.evaluate(element => element.scrollIntoView({ block: 'start' }));
      const from = await handle(expected[0]!).boundingBox(), to = await row(expected[1]!).boundingBox();
      if (!from || !to) throw new Error('Touch ordering targets are unavailable');
      const x = from.x + from.width / 2, y = from.y + from.height / 2, end = to.y + to.height - 10;
      await session.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x, y }] });
      for (let step = 1; step <= 12; step++) await session.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [{ x, y: y + (end - y) * step / 12 }] });
      await expect(page.locator('.task-drag-preview')).toBeVisible();
      await session.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
      expected = [expected[1]!, expected[0]!, expected[2]!];
      await expect.poll(() => titles(group)).toEqual(expected); await settled();
      await expect(handle(expected[1]!)).toBeFocused();
      await session.send('Emulation.setTouchEmulationEnabled', { enabled: false }); await session.detach();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.evaluate(() => scrollTo({ top: 0, behavior: 'instant' }));
    await expect.poll(() => page.evaluate(() => scrollY)).toBe(0);
    await page.screenshot({ path: testInfo.outputPath('task-order-mobile.png'), fullPage: true, animations: 'disabled' });
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.evaluate(() => scrollTo({ top: 0, behavior: 'instant' }));
    await expect.poll(() => page.evaluate(() => scrollY)).toBe(0);
    await page.screenshot({ path: testInfo.outputPath('task-order-desktop.png'), fullPage: true, animations: 'disabled' });
    stage = 'licence restriction and reload';
    await fixture.restrictLicence(); await page.reload(); await signIn(page);
    await navigate(page, `/projects/${projectId}/work`);
    await expect.poll(() => titles(group)).toEqual(expected);
    await expect(group.locator('.task-drag-handle')).toHaveCount(0);
    if (errors.length) await testInfo.attach('task-order-transport-stages', { body: JSON.stringify(transportEvents, null, 2), contentType: 'application/json' });
    // WebKit reports this handled fetch cancellation as a Console.messageAdded
    // JavaScript error during unload; Playwright forwards it as pageerror. Keep
    // the warning attached, while all actual DOM errors/rejections still fail.
    // Reload may cancel the delivery or its history request before a subsequent
    // delivery fetch is refused by the closing document.
    const unloadWarnings = pageErrors.filter(error => testInfo.project.name === 'webkit'
      && error.stage === 'licence restriction and reload' && cancelledDelivery.has(error.stage) && !rejectedDelivery.has(error.stage)
      && error.message === `/${new URL(page.url()).host}/v1/auth/access-change/delivery due to access control checks.`
      && error.stack.startsWith('Fetch API cannot load /v1/auth/access-change/delivery due to access control checks.')
      && error.stack.includes('at post ('));
    if (unloadWarnings.length) testInfo.annotations.push({ type: 'WebKit unload warning', description: 'A cancelled access refresh was reported by the browser engine during the licence-restriction reload; no DOM exception or unhandled rejection is allowed.' });
    expect(unloadWarnings.length).toBeLessThanOrEqual(1);
    expect(windowErrors).toEqual([]);
    expect(errors).toEqual(pageErrors.map(error => error.message));
    expect(pageErrors.filter(error => !unloadWarnings.includes(error))).toEqual([]);
  } finally { await page.close(); await fixture.close(); }
});
