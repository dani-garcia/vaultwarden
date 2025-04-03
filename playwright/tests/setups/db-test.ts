import { test as base } from '@playwright/test';

export type TestOptions = {
  serviceName: string;
};

export const test = base.extend<TestOptions>({
  serviceName: ['', { option: true }],
});
