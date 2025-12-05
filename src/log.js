// src/log.js

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

// e.g. LOG_LEVEL=debug node dist/demo.js
const envLevel = (process.env.LOG_LEVEL || 'info').toLowerCase();
const CURRENT_LEVEL = LEVELS[envLevel] ?? LEVELS.info;

// optional: LOG_FORMAT=plain | json
const LOG_FORMAT = (process.env.LOG_FORMAT || 'plain').toLowerCase();

function log(level, msg, context) {
  if (LEVELS[level] > CURRENT_LEVEL) return;

  if (LOG_FORMAT === 'json') {
    const payload = {
      level,
      ts: new Date().toISOString(),
      msg,
      ...context,
    };
    // use stdout for info/debug, stderr for error if you like
    if (level === 'error') {
      console.error(JSON.stringify(payload));
    } else {
      console.log(JSON.stringify(payload));
    }
  } else {
    // human-readable, phase/step oriented
    if (context && Object.keys(context).length) {
      console.log(`[${level.toUpperCase()}] ${msg}`, context);
    } else {
      console.log(`[${level.toUpperCase()}] ${msg}`);
    }
  }
}

export const logger = {
  error: (msg, ctx = {}) => log('error', msg, ctx),
  warn:  (msg, ctx = {}) => log('warn',  msg, ctx),
  info:  (msg, ctx = {}) => log('info',  msg, ctx),
  debug: (msg, ctx = {}) => log('debug', msg, ctx),
};
