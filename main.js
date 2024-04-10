// aim server lol

const logger = require("./modules/logger");
const mysql = require("./modules/mysql");
const FLAP = require("./modules/FLAP")
const SNAC = require("./modules/SNAC")
const TLV = require("./modules/TLV")
const BOS = require("./BOS")
const net = require("net");

logger.info(`Authorization server launched on port ${5190}`)

net.createServer(function (socket) { // start listening
    var flapSequence = 0x0000
    var localUser

    socket.write(FLAP.constructFLAP(0x01, flapSequence += 1, "00000001"))

    socket.on('data', function (data) {
        async function handleData(packet) {
            try {
                // (trying to) writing out non nested code :D
                var flapData = await FLAP.decodeFLAP(packet)
                switch (flapData.type) {
                    case 1:
                        // FLAP__FRAME_SIGNON
                        if (data.includes(0x2a02)) { // this maybe could be implemented better
                            handleData(data.slice(flapData.data.length - 6, data.length)) // another dirty hack
                        }
                        break;
                    case 2:
                        // FLAP__FRAME_DATA
                        var snacData = await SNAC.decodeSNAC(flapData.data)
                        var tlvData = await TLV.decodeTLV(snacData.data)

                        async function subgroup(subgroup) {
                            switch (subgroup) {
                                case 0x0006:
                                    // BUCP__CHALLENGE_REQUEST
                                    var authKey = Buffer.from(`authkey`, 'utf8')
                                    var authKeyPreamble = Buffer.alloc(4)
                                    authKeyPreamble.writeUint32BE(authKey.length)
                                    var finalData = Buffer.concat([authKeyPreamble, authKey])

                                    socket.write(FLAP.constructFLAP(0x02, flapSequence += 1, SNAC.constructSNAC(0x0017, 0x0007, 0x0000, 0x00000000, finalData)))
                                    break;
                                case 0x0002:
                                    // BUCP__LOGIN_REQUEST
                                    // let's break this down..
                                    function createRandomString(length) { // thanks internet!
                                        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                                        let result = "";
                                        for (let i = 0; i < length; i++) {
                                            result += chars.charAt(Math.floor(Math.random() * chars.length));
                                        }
                                        return result;
                                    }
                                    var authorizationKey = createRandomString(64)
                                    localUser = tlvData
                                    localUser.socket = socket
                                    // we save our clients data in "localUser" to used later
                                    var errorTLV = TLV.constructTLV([
                                        { type: 0x0001, value: localUser.username }, { type: 0x0008, value: 0x0008 }, { type: 0x0004, value: "https://lush16.net" }
                                    ])
                                    // ^ this set of TLVS contains all the errors that would inform the user that they were authorized
                                    var successTLV = TLV.constructTLV([
                                        { type: 0x0001, value: localUser.username }, { type: 0x0005, value: "192.168.0.94:5191" }, { type: 0x0006, value: authorizationKey }, { type: 0x0011, value: "test@email.com" }
                                    ])
                                    // ^ this set of TLVS contains the data needed to successfully authorize someone into the network
                                    var sendBOS = BOS.sendUser({ "username": localUser.username, "authorization": authorizationKey })
                                    socket.write(FLAP.constructFLAP(0x02, flapSequence += 1, SNAC.constructSNAC(0x0017, 0x0003, 0x0000, 0x00000000, successTLV)))
                                    // ^ this actually sends the data to the client
                                    logger.info(`${localUser.socket.remoteAddress} is connecting with username '${localUser.username}' on ${localUser.clientidentitystring}`)
                                    break;
                                default:
                                    logger.error(`unknown subgroup :P | ${subgroup.toString(16).padStart(4, 0)}`)
                                    break;
                            }
                        }

                        switch (snacData.foodgroup) {
                            case 0x0017:
                                // BUCP
                                subgroup(snacData.subgroup)
                                break;
                            default:
                                logger.error(`unknown foodgroup :P | ${snacData.foodgroup.toString(16).padStart(4, 0)}`)
                                break;
                        }
                        break;
                    case 0x0003:
                        // FLAP__FRAME_ERROR 
                        // todo
                        break;
                    case 0x0004:
                        // FLAP__FRAME_SIGNOFF
                        // todo
                        break;
                    case 0x0003:
                        // FLAP__FRAME_KEEP_ALIVE 
                        // todo (although there shouldn't be really much to handle here because the server shouldn't respond)
                        break;
                    default:
                        logger.error(`unknown flap type :P | ${flapData.type.toString(16).padStart(4, 0)}`)
                        break;
                }
            } catch (err) {
                logger.error(err)
            }
        }

        handleData(data)
    });
    // todo: get host and port from .env
}).listen(5190, `192.168.0.94`);


process.on('uncaughtException', function (err) {
    logger.error(err.stack);
});