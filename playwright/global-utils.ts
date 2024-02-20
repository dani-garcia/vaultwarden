import { type Browser, type TestInfo } from '@playwright/test';
import { execSync } from 'node:child_process';
import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';

const fs = require("fs");
const { spawn } = require('node:child_process');

function loadEnv(){
    var myEnv = dotenv.config({ path: 'test.env' });
    dotenvExpand.expand(myEnv);
}

async function waitFor(url: String, browser: Browser) {
    var ready = false;
    var context;

    do {
        try {
            context = await browser.newContext();
            const page = await context.newPage();
            await page.waitForTimeout(500);
            const result = await page.goto(url);
            ready = result.status() === 200;
        } catch(e) {
            if( !e.message.includes("CONNECTION_REFUSED") ){
                throw e;
            }
        } finally {
            await context.close();
        }
    } while(!ready);
}

function startStopSqlite(){
    fs.rmSync("temp/db.sqlite3", { force: true });
    fs.rmSync("temp/db.sqlite3-shm", { force: true });
    fs.rmSync("temp/db.sqlite3-wal", { force: true });
}

function startMariaDB() {
    console.log(`Starting MariaDB`);
    execSync(`docker run --rm --name ${process.env.MARIADB_CONTAINER} \
        -e MARIADB_ROOT_PASSWORD=${process.env.MARIADB_PWD} \
        -e MARIADB_USER=${process.env.MARIADB_USER} \
        -e MARIADB_PASSWORD=${process.env.MARIADB_PWD} \
        -e MARIADB_DATABASE=${process.env.MARIADB_DB} \
        -p ${process.env.MARIADB_PORT}:3306 \
        -d mariadb:10.4`
    );
}


function stopMariaDB() {
    console.log("Stopping MariaDB (ensure DB is wiped)");
    execSync(`docker stop ${process.env.MARIADB_CONTAINER}  || true`);
}

function startPostgres() {
    console.log(`Starting Postgres`);
    execSync(`docker run --rm --name ${process.env.POSTGRES_CONTAINER} \
        -e POSTGRES_USER=${process.env.POSTGRES_USER} \
        -e POSTGRES_PASSWORD=${process.env.POSTGRES_PWD} \
        -e POSTGRES_DB=${process.env.POSTGRES_DB} \
        -p ${process.env.POSTGRES_PORT}:5432 \
        -d postgres:16.2`
    );
};

function stopPostgres() {
    console.log("Stopping Postgres (Ensure DB is wiped)");
    execSync(`docker stop ${process.env.POSTGRES_CONTAINER}  || true`);
}

function dbConfig(testInfo: TestInfo){
    switch(testInfo.project.name) {
        case "postgres": return {
            DATABASE_URL: `postgresql://${process.env.POSTGRES_USER}:${process.env.POSTGRES_PWD}@127.0.0.1:${process.env.POSTGRES_PORT}/${process.env.POSTGRES_DB}`
        }
        case "mysql": return {
            DATABASE_URL: `mysql://${process.env.MARIADB_USER}:${process.env.MARIADB_PWD}@127.0.0.1:${process.env.MARIADB_PORT}/${process.env.MARIADB_DB}`
        }
        default: return { I_REALLY_WANT_VOLATILE_STORAGE: true }
    }
}

async function startVaultwarden(browser: Browser, testInfo: TestInfo, env = {}, resetDB: Boolean = true) {
    if( resetDB ){
        switch(testInfo.project.name) {
            case "postgres":
                stopPostgres();
                startPostgres()
                break;
            case "mysql":
                stopMariaDB();
                startMariaDB();
                break;
            default:
                startStopSqlite();
        }
    }

    const vw_log = fs.openSync("temp/logs/vaultwarden.log", "a");
    var proc = spawn("temp/vaultwarden", {
        env: { ...process.env, ...env, ...dbConfig(testInfo) },
        stdio: [process.stdin, vw_log, vw_log]
    });

    await waitFor("/", browser);

    console.log(`Vaultwarden running on: ${process.env.DOMAIN}`);

    return proc;
}

async function stopVaultwarden(proc, testInfo: TestInfo, resetDB: Boolean = true) {
    console.log(`Vaultwarden stopping`);
    proc.kill();

    if( resetDB ){
        switch(testInfo.project.name) {
            case "postgres":
                stopPostgres();
                break;
            case "mysql":
                stopMariaDB();
                break;
            default:
                startStopSqlite();
        }
    }
}

async function restartVaultwarden(proc, page: Page, testInfo: TestInfo, env, resetDB: Boolean = true) {
    stopVaultwarden(proc, testInfo, resetDB);
    return startVaultwarden(page.context().browser(), testInfo, env, resetDB);
}

export { loadEnv, waitFor, startVaultwarden, stopVaultwarden, restartVaultwarden };
