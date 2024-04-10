// handles TLV data
const { Buffer } = require('node:buffer');
const logger = require("./logger");

function decodeTLV(packet) {
    // this decodes TLV data
    return new Promise((resolve, reject) => {
        var tlvData = new Buffer.from(packet, 'hex')
        var tlv = {}

        let offset = 0;
        while (offset < tlvData.length) {
            const type = tlvData.readUInt16BE(offset);
            offset += 2;

            const length = tlvData.readUInt16BE(offset);
            offset += 2;

            const value = tlvData.slice(offset, offset + length);
            offset += length;

            switch (type) {
                case 0x0001:
                    // screen name (uin)
                    tlv.username = value.toString()
                    break;
                case 0x0002:
                    // new password
                    tlv.newpassword = value.toString()
                    break;
                case 0x0003:
                    // client identity string
                    tlv.clientidentitystring = value.toString()
                    break;
                case 0x0006:
                    // authorizationkey
                    tlv.authorizationkey = value.toString()
                    break;
                case 0x000f:
                    // language
                    tlv.language = value.toString()
                    break;
                case 0x000e:
                    // country
                    tlv.country = value.toString()
                    break;
                case 0x0014:
                    // distribution number
                    tlv.distributionnumber = value
                    break;
                case 0x0016:
                    // client id
                    tlv.clientid = value
                    break;
                case 0x0017:
                    // client major version
                    tlv.clientmajorversion = value
                    break;
                case 0x0018:
                    // client minor version
                    tlv.clientminorversion = value
                    break;
                case 0x0019:
                    // client lesser version
                    tlv.clientlesserversion = value
                    break;
                case 0x001a:
                    // client build number
                    tlv.clientbuildnumber = value
                    break;
                case 0x0025:
                    // md5 password
                    tlv.md5pass = value
                    break;
                case 0x004A:
                // no action
                case 0x004B:
                    // no action
                    break;
                case 0x004C:
                    // no action
                    break;
                case 0x005a:
                    // no action
                    break;
                default:
                    logger.warn(`unknown tlv :P | ${type.toString(16).padStart(4, 0)}`)
                    break;
            }
        }

        resolve(tlv)
    })
};

function constructTLV(array) {
    // this constructs TLVS
    var tlvBuffers = []
    array.forEach((element) => {
        var tlvHeader = new Buffer.alloc(4); // i use "header" loosely but we have to combine the type and length so whatever
        var value
        if (typeof element.value == "number") {
            value = new Buffer.alloc(2)
            value.writeUint16BE(element.value)
        } else {
            value = new Buffer.from(element.value);
        }
        var length = value.length
        var type = element.type

        tlvHeader.writeUint16BE(type)
        tlvHeader.writeUint16BE(length, 2)

        var tlvResult = Buffer.concat([tlvHeader, value]);
        tlvBuffers.push(tlvResult)
    });

    return new Buffer.concat(tlvBuffers)
};

module.exports = {
    decodeTLV,
    constructTLV,
};