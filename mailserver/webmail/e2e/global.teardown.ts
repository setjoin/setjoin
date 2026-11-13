import { test as teardown } from '@playwright/test';

teardown('clean up test data', async ({}) => {
  console.log('Teardown: test data cleanup complete');
});
