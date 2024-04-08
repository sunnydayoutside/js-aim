// aim server lol

const logger = require("./modules/logger");
const mysql = require("./modules/mysql");
const FLAP = require("./modules/FLAP")
const SNAC = require("./modules/SNAC")
const TLV = require("./modules/TLV")
const net = require("net");

const users = []

net.createServer(function (socket) { // start listening
    var flapSequence = 0x0000

    socket.write(FLAP.constructFLAP(0x01, flapSequence += 1, "00000001"))

    socket.on('data', function (data) {
        FLAP.decodeFLAP(data).then((result) => {
            switch (result.type) {
                case 0x01:
                    break;
                case 0x02:
                    SNAC.decodeSNAC(result.data).then((snacresult) => {
                        function subgroup(subgroup) {
                            switch (subgroup) {
                                case 0x0006:
                                    // BUCP__CHALLENGE_REQUEST
                                    var authKey = Buffer.from(`hi`, 'utf8')
                                    var authKeyPreamble = Buffer.alloc(4)
                                    authKeyPreamble.writeUint32BE(authKey.length)
                                    TLV.decodeTLV(snacresult.data).then((tlvresult) => {
                                        var finalData = Buffer.concat([authKeyPreamble, authKey])
                                        var found = tlvresult.find(function (element) {
                                            return element.type = 1
                                        });

                                        logger.info(`${socket.remoteAddress} is attempting to log in with username '${found.value.toString()}'`)
                                        socket.write(FLAP.constructFLAP(0x02, flapSequence += 1, SNAC.constructSNAC(0x0017, 0x0007, 0x0000, 0x00000000, finalData)))
                                    }).catch((err) => {
                                        logger.error(err)
                                    })
                                    break;
                                case 0x0002:
                                    // BUCP__LOGIN_REQUEST
                                    TLV.decodeTLV(snacresult.data).then((tlvresult) => {
                                        console.log(tlvresult)
                                    }).catch((err) => {
                                        logger.error(err)
                                    })
                                    break;
                                default:
                                    logger.error(`unknown subgroup :P | ${subgroup.toString(16).padStart(4,0)}`)
                                    break;
                            }
                        }

                        switch (snacresult.foodgroup) {
                            case 0x0017:
                                // BUCP
                                subgroup(snacresult.subgroup)
                                break;
                            default:
                                logger.error(`unknown foodgroup :P | ${snacresult.foodgroup.toString(16).padStart(4,0)}`)
                                break;
                        }
                    }).catch((err) => {
                        logger.error(err)
                    })
                    break;
                default:
                    break;
            }
        }).catch((err) => {
            logger.error(err)
        })
    });
}).listen(5190, `192.168.0.94`);
