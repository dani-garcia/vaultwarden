import { test } from './db-test';

const utils = require('../../global-utils');

utils.loadEnv();

test('DB teardown ?', async ({ serviceName }) => {
    if( process.env.PW_KEEP_SERVICE_RUNNNING !== "true" ) {
        utils.stopComposeService(serviceName);
    }
});
