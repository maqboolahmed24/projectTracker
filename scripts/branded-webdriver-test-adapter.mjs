// The existing pure browser specifications keep their original Playwright assertions.
// Only test registration and the small browser-driver surface are adapted.
export { expect } from '@playwright/test';
export const registeredTests = [];
export function test(name, run) { registeredTests.push({ name, run }); }
