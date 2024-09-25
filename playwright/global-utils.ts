import { type Browser, type TestInfo } from '@playwright/test';
import { EventEmitter } from "events";
import { type Mail, MailServer } from 'maildev';
import { execSync } from 'node:child_process';

import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';

const fs = require("fs");
const { spawn } = require('node:child_process');

export function loadEnv(){
    var myEnv = dotenv.config({ path: 'test.env' });
    dotenvExpand.expand(myEnv);

    return {
        user1: {
            email: process.env.TEST_USER_MAIL,
            name: process.env.TEST_USER,
            password: process.env.TEST_USER_PASSWORD,
        },
        user2: {
            email: process.env.TEST_USER2_MAIL,
            name: process.env.TEST_USER2,
            password: process.env.TEST_USER2_PASSWORD,
        },
        user3: {
            email: process.env.TEST_USER3_MAIL,
            name: process.env.TEST_USER3,
            password: process.env.TEST_USER3_PASSWORD,
        },
    }
}

export function closeMails(mailServer: MailServer, mailIterators: AsyncIterator<Mail>[]) {
    if( mailServer ) {
        mailServer.close();
    }
    if( mailIterators ) {
        for (const mails of mailIterators) {
            if(mails){
                mails.return();
            }
        }
    }
}

export async function waitFor(url: String, browser: Browser) {
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

export function startComposeService(serviceName: String){
    console.log(`Starting ${serviceName}`);
    execSync(`docker compose --profile playwright --env-file test.env  up -d ${serviceName}`);
}

export function stopComposeService(serviceName: String){
    console.log(`Stopping ${serviceName}`);
    execSync(`docker compose --profile playwright --env-file test.env  stop ${serviceName}`);
}

function wipeSqlite(){
    console.log(`Delete Vaultwarden container to wipe sqlite`);
    execSync(`docker compose --env-file test.env stop Vaultwarden`);
    execSync(`docker compose --env-file test.env rm -f Vaultwarden`);
}

async function wipeMariaDB(){
    var mysql = require('mysql2/promise');
    var ready = false;
    var connection;

    do {
        try {
            connection = await mysql.createConnection({
                user: process.env.MARIADB_USER,
                host: "127.0.0.1",
                database: process.env.MARIADB_DATABASE,
                password: process.env.MARIADB_PASSWORD,
                port: process.env.MARIADB_PORT,
            });

            await connection.execute(`DROP DATABASE ${process.env.MARIADB_DATABASE}`);
            await connection.execute(`CREATE DATABASE ${process.env.MARIADB_DATABASE}`);
            console.log('Successfully wiped mariadb');
            ready = true;
        } catch (err) {
            console.log(`Error when wiping mariadb: ${err}`);
        } finally {
            if( connection ){
                connection.end();
            }
        }
        await new Promise(r => setTimeout(r, 1000));
    } while(!ready);
}

async function wipeMysqlDB(){
    var mysql = require('mysql2/promise');
    var ready = false;
    var connection;

    do{
        try {
            connection = await mysql.createConnection({
                user: process.env.MYSQL_USER,
                host: "127.0.0.1",
                database: process.env.MYSQL_DATABASE,
                password: process.env.MYSQL_PASSWORD,
                port: process.env.MYSQL_PORT,
            });

            await connection.execute(`DROP DATABASE ${process.env.MYSQL_DATABASE}`);
            await connection.execute(`CREATE DATABASE ${process.env.MYSQL_DATABASE}`);
            console.log('Successfully wiped mysql');
            ready = true;
        } catch (err) {
            console.log(`Error when wiping mysql: ${err}`);
        } finally {
            if( connection ){
                connection.end();
            }
        }
        await new Promise(r => setTimeout(r, 1000));
    } while(!ready);
}

async function wipePostgres(){
    const { Client } = require('pg');

    const client = new Client({
        user: process.env.POSTGRES_USER,
        host: "127.0.0.1",
        database: "postgres",
        password: process.env.POSTGRES_PASSWORD,
        port: process.env.POSTGRES_PORT,
    });

    try {
        await client.connect();
        await client.query(`DROP DATABASE ${process.env.POSTGRES_DB}`);
        await client.query(`CREATE DATABASE ${process.env.POSTGRES_DB}`);
        console.log('Successfully wiped postgres');
    } catch (err) {
        console.log(`Error when wiping postgres: ${err}`);
    } finally {
        client.end();
    }
}

function dbConfig(testInfo: TestInfo){
    switch(testInfo.project.name) {
        case "postgres": return {
            DATABASE_URL: `postgresql://${process.env.POSTGRES_USER}:${process.env.POSTGRES_PASSWORD}@127.0.0.1:${process.env.POSTGRES_PORT}/${process.env.POSTGRES_DB}`
        }
        case "mariadb": return {
            DATABASE_URL: `mysql://${process.env.MARIADB_USER}:${process.env.MARIADB_PASSWORD}@127.0.0.1:${process.env.MARIADB_PORT}/${process.env.MARIADB_DATABASE}`
        }
        case "mysql": return {
            DATABASE_URL: `mysql://${process.env.MYSQL_USER}:${process.env.MYSQL_PASSWORD}@127.0.0.1:${process.env.MYSQL_PORT}/${process.env.MYSQL_DATABASE}`
        }
        default: return { I_REALLY_WANT_VOLATILE_STORAGE: true }
    }
}

/**
 *  All parameters passed in `env` need to be added to the docker-compose.yml
 **/
export async function startVaultwarden(browser: Browser, testInfo: TestInfo, env = {}, resetDB: Boolean = true) {
    if( resetDB ){
        switch(testInfo.project.name) {
            case "postgres":
                await wipePostgres();
                break;
            case "mariadb":
                await wipeMariaDB();
                break;
            case "mysql":
                await wipeMysqlDB();
                break;
            default:
                wipeSqlite();
        }
    }

    console.log(`Starting Vaultwarden`);
    execSync(`docker compose --profile playwright --env-file test.env up -d Vaultwarden`, {
        env: { ...env, ...dbConfig(testInfo) },
    });
    await waitFor("/", browser);
    console.log(`Vaultwarden running on: ${process.env.DOMAIN}`);
}

export async function stopVaultwarden() {
    console.log(`Vaultwarden stopping`);
    execSync(`docker compose --profile playwright --env-file test.env stop Vaultwarden`);
}

export async function restartVaultwarden(page: Page, testInfo: TestInfo, env, resetDB: Boolean = true) {
    stopVaultwarden();
    return startVaultwarden(page.context().browser(), testInfo, env, resetDB);
}
