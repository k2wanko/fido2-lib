/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place

"use strict";

const {
    printHex,
    coerceToArrayBuffer,
    coerceToBase64,
    abToBuf,
    abToPem,
    ab2str,
    b64ToJsObject
} = require("../utils");
const crypto = require("crypto");
const {
    CertManager
} = require("../certUtils");
const jose = require("node-jose");

function androidSafetyNetParseFn(attStmt) {
    var ret = new Map();

    // console.log("android-safetynet", attStmt);

    ret.set("ver", attStmt.ver);

    var response = ab2str(attStmt.response);
    ret.set("response", response);

    // console.log("returning", ret);
    return ret;
}

async function androidSafetyNetValidateFn() {
    this.audit.journal.add("challenge");
    this.audit.journal.add("origin");
    this.audit.journal.add("type");
    this.audit.journal.add("tokenBinding");
    this.audit.journal.add("rawClientDataJson");
    this.audit.journal.add("rawId");
    this.audit.journal.add("fmt");
    this.audit.journal.add("ver");
    this.audit.journal.add("response");
    this.audit.journal.add("rawAuthnrData");
    this.audit.journal.add("rpIdHash");
    this.audit.journal.add("flags");
    this.audit.journal.add("counter");
    this.audit.journal.add("aaguid");
    this.audit.journal.add("credIdLen");
    this.audit.journal.add("credId");
    this.audit.journal.add("credentialPublicKeyCose");
    this.audit.journal.add("credentialPublicKeyJwk");
    this.audit.journal.add("credentialPublicKeyPem");
    this.audit.journal.add("payload");
    this.audit.journal.add("attCert");
    this.audit.journal.add("x5c");

    var response = this.authnrData.get("response");

    // parse JWS
    var parsedJws = await jose.JWS.createVerify().verify(response, { allowEmbeddedKey: true });
    this.authnrData.set("payload", JSON.parse(ab2str(coerceToArrayBuffer(parsedJws.payload, "MDS TOC payload"))));

    // get certs
    this.authnrData.set("attCert", parsedJws.header.x5c.shift());
    this.authnrData.set("x5c", parsedJws.header.x5c);

    // // verify cert chain
    // var rootCerts;
    // if (Array.isArray(rootCert)) rootCerts = rootCert;
    // else rootCerts = [rootCert];
    // var ret = await CertManager.verifyCertChain(header.x5c, rootCerts, crls);
    return true
}

module.exports = {
    name: "android-safetynet",
    parseFn: androidSafetyNetParseFn,
    validateFn: androidSafetyNetValidateFn
};
