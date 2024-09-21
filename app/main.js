const dgram = require("dgram");

const clientSocket = dgram.createSocket("udp4");
clientSocket.bind(2053, "127.0.0.1");

const {ip , port} = parseForwardAddress();

clientSocket.on("message", (buf, rinfo) => {
    try {
        const dnsPacket = parseDNSpacket(buf);

        // Upstream Forward DNS Query
        const dnsBuffers = parseDNSPacketToBuffer(dnsPacket);
        forwardBuffers(dnsBuffers, port, ip, rinfo);

        // Normal DNS Query
        // const dnsResponse = createDNSResponse(dnsPacket);
        // clientSocket.send(dnsResponse, rinfo.port, rinfo.address);
    } catch (e) {
        console.log(`Error receiving data: ${e}`);
    }
});

clientSocket.on("error", (err) => {
    console.log(`Error: ${err}`);
});

clientSocket.on("listening", () => {
    const address = clientSocket.address();
    console.log(`Server listening ${address.address}:${address.port}`);
});


async function forwardBuffers(buffers, port, ip, rinfo) {
    const promises = [];

    for (const buffer of buffers) {
        promises.push(forwardDNSServer(buffer, port, ip, rinfo));
    }

    await Promise.all(promises);
}

async function forwardDNSServer(dnsPacket, port, ip, clientInfo) {
    const upstreamSocket = dgram.createSocket("udp4");

    await new Promise((resolve, reject) => {
        upstreamSocket.send(dnsPacket, port, ip, (err) => {
            if (err) {
                console.log(`Failed to forward query to upstream DNS: ${err.message}`);
                upstreamSocket.close();
                return reject(err);
            }
            console.log(`Forwarded DNS query to ${ip}:${port}`);
            resolve();
        });
    });
    
    await new Promise((resolve, reject) => {
        upstreamSocket.on('message', (response) => {
            console.log('Received response from upstream DNS');
            
            clientSocket.send(response, clientInfo.port, clientInfo.address, (err) => {
                if (err) {
                    console.log(`Failed to send response to client: ${err.message}`);
                    return reject(err);
                } else {
                    console.log(`Sent response to ${clientInfo.address}:${clientInfo.port}`);
                    resolve();
                }
            });
            upstreamSocket.close();
        });

        upstreamSocket.on('error', (err) => {
            console.error(`Error with upstream socket: ${err.stack}`);
            upstreamSocket.close();
            reject(err);
        });
    });
}


function parseDNSPacketToBuffer(dnsPacket) {
    const queryHeader = dnsPacket.header;
    const queryQuestions = dnsPacket.questions;
    console.log(queryQuestions);
    
    const headerBuffer = createDNSHeader(
        queryHeader.ID, 
        1,
        queryHeader.OPCODE,
        0,
        0,
        queryHeader.RD,
        0,
        0,
        queryHeader.OPCODE == 0 ? 0 : 4, 
        1,
        0,
        0,
        0
    );

    let packetBuffers = [];
    for (let i = 0; i < queryQuestions.length; i++) {
        const questionBuffer = createDNSQuestion(queryQuestions[i].domain, queryQuestions[i].type, queryQuestions[i].class);

        packetBuffers.push(Buffer.concat([headerBuffer, questionBuffer]));
    }
    console.log(packetBuffers);
    return packetBuffers;
}

function parseForwardAddress() {
    const args = process.argv;
    const resolverIndex = args.indexOf('--resolver');
    if (resolverIndex !== -1 && resolverIndex + 1 < args.length) {
        const address = args[resolverIndex + 1];
        const ip = address.split(":")[0];
        const port = parseInt(address.split(":")[1]);
        return { ip , port };
    } else {
        console.log('Error: --resolver flag or address missing');
        process.exit(1);
    }
}

function isCompressed(buf, offset) {
    // Read the first byte at the specified offset
    const firstByte = buf.readUInt8(offset);

    // console.log(`First byte (decimal): ${firstByte}`);
    // console.log(`First byte (hex): 0x${firstByte.toString(16).toUpperCase()}`);
    // console.log(`First byte (binary): ${firstByte.toString(2).padStart(8, '0')}`);

    // Log the result of masking with 0xC0 (binary 11000000)
    const maskedValue = firstByte & 0xC0;
    // console.log(`Masked first byte (binary): ${maskedValue.toString(2).padStart(8, '0')}`);
    
    // Check if the first two bits are `11` (i.e., 0xC0)
    const isCompressed = (maskedValue === 0xC0);
    
    return (firstByte & 0xc0) === 0xc0;
}

function parseCompressedDomain(buf, pointer) {
    let domainParts = [];
    let i = pointer;

    while (buf[i] !== 0) {
        let length = buf[i];
        i++;
        let part = buf.slice(i, i + length).toString('ascii');
        domainParts.push(part);
        i += length;
    }
    // console.log(domainParts);
    
    return { domainParts };
}


function parseDNSpacket(buf) {
    const header = parseHeader(buf);
    const questionOffset = 12;
    const {questions} = parseQuestion(buf, questionOffset, header.QDCOUNT);

    // console.log(questions);
    
    return {
        header,
        questions
    }
}

function parseHeader(buf) {
    const dnsHeader = {
        // First 16 bits
        ID: buf.readUInt16BE(0),

        // Next 8 bits -> QR, OPCODE (4bits), AA, TC, RD
        QR: buf.readUint8(2) >> 7,
        OPCODE: (buf.readUint8(2) >> 3) & 0b1111,
        AA: (buf.readUint8(2) >> 2) & 0b1,
        TC: (buf.readUint8(2) >> 1) & 0b1,
        RD: buf.readUint8(2) & 0b1,

        // Next 8 bits -> RA, Z (3 bits), RCODE (4 bits)
        RA: (buf.readUint8(3) >> 7) & 0b1,
        Z: (buf.readUint8(3) >> 4) & 0b111,
        RCODE: buf.readUint8(3) & 0b1111,

        // Next 16 bits
        QDCOUNT: buf.readUInt16BE(4),
        ANCOUNT: buf.readUInt16BE(6),
        NSCOUNT: buf.readUInt16BE(8),
        ARCOUNT: buf.readUInt16BE(10),
    };
    return dnsHeader;
}

function parseQuestion(buf, offset, qdCount) {
    let j = 0;
    let questions = [];
    let i = offset;
    let jumped = false;
    let jumpOffset = 0;

    while (j < qdCount) {
        // console.log(`This is i: ${i} and buffer length is ${buf.length}`);
        
        let question = {};
        let domainParts = [];

        // Start parsing the domain name
        while (buf[i] !== 0) { // Stop at the null byte
            if (isCompressed(buf, i)) {
                // Handle compression
                const pointer = ((buf.readUInt8(i) & 0x3F) << 8) | buf.readUInt8(i + 1); // Get 14-bit pointer
                i += 2; // Move past the compression pointer

                if (!jumped) {
                    jumpOffset = i; // Save the current position to return after parsing compressed domain
                }

                // Parse the compressed domain from the pointer location
                const parsed = parseCompressedDomain(buf, pointer);
                domainParts = domainParts.concat(parsed.domainParts); // Append the domain parts
                jumped = true;
                break; // Compression points to an already completed domain, no need to parse further
            } else {
                // Parse uncompressed label
                let length = buf[i]; // First byte is the length of the label
                i++; // Move to the first character of the label
                let part = buf.slice(i, i + length).toString('ascii'); // Extract the label
                domainParts.push(part); // Add the label to domain parts
                i += length; // Move to the next length byte
            }
        }

        // Compressed names do not have a null byte at the end
        if (!jumped) {
            i++; // Move past the null byte
        }

        // Join the domain parts to form the full domain name
        question.domain = domainParts.join('.');


        // Ensure enough bytes are available before reading the type and class
        if (i + 4 > buf.length) {
            throw new RangeError(`Not enough bytes to read type and class at i: ${i}`);
        }

        // console.log(`This is i before reading type: ${i} out of ${buf.length}`);
        
        // Read the question type and class (each 2 bytes)
        question.type = buf.readUInt16BE(i);
        i += 2;

        // console.log(`This is i before reading class: ${i} out of ${buf.length}`);
        question.class = buf.readUInt16BE(i);
        i += 2;

        // Add the question to the list of questions
        questions.push(question);
        j++;

        // If a jump happened (due to compression), return to where we left off in the original packet
        if (jumped && jumpOffset > 0) {
            i = jumpOffset;
            jumped = false;
        }
    }

    return { questions, i };
}

function createDNSResponse(dnsPacket) {
    const queryHeader = dnsPacket.header;
    const queryQuestions = dnsPacket.questions;

    const headerBuffer = createDNSHeader(
        queryHeader.ID, 
        1,
        queryHeader.OPCODE,
        0,
        0,
        queryHeader.RD,
        0,
        0,
        queryHeader.OPCODE == 0 ? 0 : 4, 
        queryQuestions.length,
        queryQuestions.length,
        0,
        0
    );

    const questionBuffers = Buffer.concat(queryQuestions.map(q => createDNSQuestion(q.domain, q.type, q.class)));

    const answerBuffers = Buffer.concat(queryQuestions.map(q => createDNSAnswer(
        q.domain,
        q.type,
        q.class,
        60,
        4,
        '8.8.8.8'
    )));

    return Buffer.concat([headerBuffer, questionBuffers, answerBuffers]);
}

function createDNSHeader(ID, QR, OPCODE, AA, TC, RD, RA, Z, RCODE, QD, AN, NS, AR) {
    const header = Buffer.alloc(12);

    let flags = 0;
    flags |= (QR << 15);
    flags |= (OPCODE << 11);
    flags |= (AA << 10);
    flags |= (TC << 9);
    flags |= (RD << 8);
    flags |= (RA << 7);
    flags |= (Z << 4);
    flags |= (RCODE);

    // console.log(flags.toString(2).padStart(16, '0'));

    header.writeUInt16BE(ID, 0); // Pocket Identifier (ID): 1234;
    header.writeUInt16BE(flags, 2); //
    header.writeUInt16BE(QD, 4); // QDCOUNT: 0
    header.writeUInt16BE(AN, 6); // ANCOUNT: 0
    header.writeUInt16BE(NS, 8); // NSCOUNT: 0
    header.writeUInt16BE(AR, 10); // ARCOUNT: 0
    return header;
}

function createDNSQuestion(name, recordType, recordClass) {
    const encodedName = encodeDomain(name);
    const question = Buffer.alloc(5 + encodedName.length);
    encodedName.copy(question, 0);
    question[encodedName.length] = 0;
    question.writeUInt16BE(recordType, encodedName.length + 1);
    question.writeUInt16BE(recordClass, encodedName.length + 3);
    return question;
}

function createDNSAnswer(name, recordType, recordClass, ttl, rDataLength, rData) {
    const encodedName = encodeDomain(name);
    const answer = Buffer.alloc(15 + encodedName.length);
    encodedName.copy(answer, 0);
    answer[encodedName.length] = 0;
    answer.writeUInt16BE(recordType, encodedName.length + 1);
    answer.writeUInt16BE(recordClass, encodedName.length + 3);
    answer.writeUInt16BE(ttl, encodedName.length + 5);
    answer.writeUInt16BE(rDataLength, encodedName.length + 9);
    const encodedIP = encodeIP(rData);
    encodedIP.copy(answer, encodedName.length + 11);
    return answer;
}


function encodeDomain(domain) {
    // console.log(isStringObject(domain));
    
    return domain.split('.').map(part => Buffer.from([part.length, ...part.split('').map(char => char.charCodeAt(0))])).reduce((prev, curr) => Buffer.concat([prev, curr]), Buffer.alloc(0));
}

function encodeIP(ip) {
    return Buffer.from(ip.split('.').map(Number)); // Convert '8.8.8.8' to [8, 8, 8, 8]
}





// console.log(calculateBytes(0));

// function calculateBytes(number) {
//     const bits = Math.ceil(Math.log2(number + 1));
//     return Math.ceil(bits / 8);
// }