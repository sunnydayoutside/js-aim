// BOS server lol

const logger = require("./modules/logger");
const mysql = require("./modules/mysql");
const FLAP = require("./modules/FLAP")
const SNAC = require("./modules/SNAC")
const TLV = require("./modules/TLV")
const net = require("net");

const users = []
const authlist = []

function sendUser(json) {
    // this allows the auth and bos server to communicate
    authlist.push(json)
}

function checkList(key) {
    var find = authlist.find((element) => element.authorizationKey == key)
    if (find) {
        return find
    } else {
        // i didn't find the specified authkey....
        return false
    }
}

logger.info(`BOS server launched on port ${5191}`)

net.createServer(function (socket) { // start listening
    var flapSequence = 0x0000
    var localUser

    socket.write(FLAP.constructFLAP(0x01, flapSequence += 1, "00000001"))

    socket.on('data', function (data) {
        async function handleData() {
            try {
                // BOS MOMENT
                var flapData = await FLAP.decodeFLAP(data)
                switch (flapData.type) {
                    case 1:
                        var loginflapData = await FLAP.decodeFLAP(data)
                        var tlvData = await TLV.decodeTLV(loginflapData.data.slice(8, loginflapData.data.length)) // dirty hack, assumes the flap packet begins with 00000001
                        var authKeyCheck = await checkList(tlvData.authorizationKey)
                        if (authKeyCheck) {
                            socket.write(FLAP.constructFLAP(0x02, flapSequence += 1, SNAC.constructSNAC(0x0001, 0x0003, 0x0000, 0x00000000, "00010002000300040017")))
                            logger.info(`'${authKeyCheck.username}' was successfully authenticated.`)
                        } else {
                            // our auth key didn't match
                            console.log(`woops`)
                        }
                        break;
                    case 2:
                        var snacData = await SNAC.decodeSNAC(flapData.data)
                        var tlvData = await TLV.decodeTLV(snacData.data)
                        
                        console.log(snacData)
                        break;
                    default:
                        break;
                }
            } catch (err) {
                logger.error(err)
            }
        }

        handleData()
    });
}).listen(5191, `192.168.0.94`);


process.on('uncaughtException', function (err) {
    logger.error(err.stack);
});

module.exports = {
    sendUser,
};