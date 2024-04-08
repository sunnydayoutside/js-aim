// handles FLAP packets
const { Buffer } = require('node:buffer');

function decodeFLAP(packet) {
    return new Promise((resolve, reject) => {
    // this decodes FLAP packets
    var flapData = new Buffer.from(packet, 'hex');

    if (flapData.readUint8(0) == 0x2A) {
        switch (flapData.readUint8(1)) {
            case 0x01:
                // FLAP__FRAME_SIGNON
                var dataParsed = flapData.slice(6, 6 + flapData.readUInt16BE(4)).toString('hex');
                var jsonResponse = {'type':flapData.readUint8(1), 'sequence':flapData.readUint16BE(2), 'length': flapData.readUInt16BE(4), 'data': dataParsed};

                resolve(jsonResponse);
                break;
            case 0x02:
                // FLAP__FRAME_DATA
                var dataParsed = flapData.slice(6, 6 + flapData.readUInt16BE(4)).toString('hex');
                var jsonResponse = {'type':flapData.readUint8(1), 'sequence':flapData.readUint16BE(2), 'length': flapData.readUInt16BE(4), 'data': dataParsed};

                resolve(jsonResponse);
                break;
            case 0x03:
                // FLAP__FRAME_ERROR
                break;
            case 0x04:
                // FLAP__FRAME_SIGNOFF
                break;
            case 0x05:
                // FLAP__FRAME_KEEP_ALIVE
                break;
            default:
                reject(false);
                break;
        }
    } else {
        // TODO: handle gracefully when inputted packet is not a FLAP packet
        reject(false);
    }
    })
};

function constructFLAP(type, sequence, data) {
    // this constructs flap packets
    var flapHeader = new Buffer.alloc(6);
    var flapData = new Buffer.from(data, 'hex');

    flapHeader.writeUInt8(0x2A); // flap marker
    flapHeader.writeUInt8(type, 1);
    flapHeader.writeUInt16BE(sequence, 2);
    flapHeader.writeUint16BE(flapData.length, 4);

    var flapResult = Buffer.concat([flapHeader, flapData]);
    return flapResult;
};

module.exports = {
    decodeFLAP,
    constructFLAP,
};