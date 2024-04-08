const log4js = require("log4js");

log4js.configure({
    appenders: {
      AIM: { type: "console" }, 
    },
    categories: {
      default: { appenders: ["AIM"], level: "all" }
     },
});

const logger = log4js.getLogger("AIM"); // not really a module but some code for log4js

module.exports = logger;