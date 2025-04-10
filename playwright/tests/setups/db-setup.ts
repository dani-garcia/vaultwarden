import { test } from './db-test';

const utils = require('../../global-utils');

test('DB start', async ({ serviceName }) => {
	utils.startComposeService(serviceName);
});
