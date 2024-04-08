const mysql = require('mysql');
const logger = require("./logger");

const database = "aim"
const table = "accounts"

const con = mysql.createConnection({
    host: "127.0.0.1",
    user: "root",
    password: "",
    database: database
});

con.connect(function (err) {
    // initiates a connection to the mysql server
    if (err) throw logger.error(err);
    logger.info(`Connected to MYSQL Database | ${database}`)
});

setInterval(function (err) {
    // this prevents a timeout from the mysql server
    if (err) throw logger.error(err);
    con.query(`SELECT * FROM ${table}`);
}, 5000);

module.exports.mysql = con;